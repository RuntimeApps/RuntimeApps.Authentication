using System.Globalization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.Verification.Services;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Features.TwoFactor.Services;

public class TwoFactorLoginService<TUser, TKey>(
    ITwoFactorChallengeStore<TKey> challengeStore,
    IEnumerable<ITwoFactorMethod<TUser>> methods,
    IOptions<TwoFactorOptions> options,
    TimeProvider timeProvider,
    IUserManager<TUser> userManager,
    IUserLockoutManager<TUser> lockoutManager,
    TwoFactorAccountEligibility<TUser, TKey> eligibility,
    IAuthenticationSessionIssuer<TUser> sessionIssuer) : ITwoFactorLoginService<TUser>
    where TUser : IdentityUser<TKey>
    where TKey : IEquatable<TKey> {
    private const int MaxChallengeLength = 256;
    private const int MaxMethodLength = 32;
    private const int MaxCodeLength = 64;
    private readonly TwoFactorOptions _options = options.Value;

    public virtual async Task<TwoFactorLoginStart> BeginAsync(TUser user, CancellationToken cancellationToken = default) {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();

        var enrolled = new List<TwoFactorMethodInfo>();
        foreach(var method in methods) {
            cancellationToken.ThrowIfCancellationRequested();
            if(await method.IsEnrolledAsync(user, cancellationToken))
                enrolled.Add(new TwoFactorMethodInfo(method.Name, method.IsDeliveryBased));
        }

        // Only the explicit opt-in lets a user without any method in; the default stays fail-closed.
        if(enrolled.Count == 0 && _options.NoEnrolledMethodBehavior == TwoFactorNoMethodBehavior.AllowSignIn)
            return TwoFactorLoginStart.SignIn();

        cancellationToken.ThrowIfCancellationRequested();
        var handle = VerificationHandle.Create();
        var now = timeProvider.GetUtcNow();
        var challenge = new TwoFactorChallenge<TKey> {
            UserId = user.Id,
            HandleHash = VerificationHandle.ComputeHash(handle),
            Status = TwoFactorChallengeStatus.Pending,
            CreatedAt = now,
            ExpiresAt = now + _options.ChallengeLifetime
        };
        await challengeStore.CreateAsync(challenge, _options.MaxPendingChallengesPerUser, cancellationToken);
        return TwoFactorLoginStart.Required(handle, challenge.ExpiresAt, enrolled);
    }

    /// <remarks>
    /// Order matters. The attempt is reserved before the code is checked so parallel guesses cannot exceed the
    /// per-challenge limit. The code is recorded as used before the challenge is consumed, and no session is issued
    /// unless every earlier step succeeded.
    /// </remarks>
    public virtual async Task<Result<TUser, Token>> CompleteAsync(string challenge, string method, string code, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        if(string.IsNullOrWhiteSpace(challenge) || challenge.Length > MaxChallengeLength ||
           string.IsNullOrWhiteSpace(method) || method.Length > MaxMethodLength ||
           string.IsNullOrWhiteSpace(code) || code.Length > MaxCodeLength)
            return AuthenticationFailed();

        var now = timeProvider.GetUtcNow();
        var stored = await challengeStore.FindByHandleHashAsync(VerificationHandle.ComputeHash(challenge), cancellationToken);
        if(stored == null || stored.Status != TwoFactorChallengeStatus.Pending || stored.ExpiresAt <= now)
            return AuthenticationFailed();
        if(!await challengeStore.TryReserveAttemptAsync(stored.Id, _options.MaxAttemptsPerChallenge, now, cancellationToken))
            return AuthenticationFailed();

        // The attempt is now spent, so every failure below also counts against the challenge.
        var user = await userManager.FindByIdAsync(Convert.ToString(stored.UserId, CultureInfo.InvariantCulture));
        if(!await eligibility.IsEligibleAsync(user, cancellationToken))
            return AuthenticationFailed();

        var selected = methods.FirstOrDefault(item => string.Equals(item.Name, method, StringComparison.OrdinalIgnoreCase));
        if(selected == null || !await selected.IsEnrolledAsync(user, cancellationToken))
            return AuthenticationFailed();
        var normalized = selected.NormalizeCode(code);
        if(normalized == null)
            return AuthenticationFailed();

        if(!await selected.VerifyAsync(user, normalized, cancellationToken)) {
            await lockoutManager.AccessFailedAsync(user);
            return AuthenticationFailed();
        }

        // Nothing is consumed yet, so honoring cancellation here cannot burn a valid code.
        cancellationToken.ThrowIfCancellationRequested();
        var codeHash = TwoFactorCodeHash.Compute(Convert.ToString(user.Id, CultureInfo.InvariantCulture), selected.Name, normalized);
        if(!await challengeStore.TryMarkCodeUsedAsync(user.Id, selected.Name, codeHash, now, now + _options.UsedCodeRetention, cancellationToken)) {
            // A correct code that was already accepted is a replay, so it counts like a wrong code.
            await lockoutManager.AccessFailedAsync(user);
            return AuthenticationFailed();
        }
        if(!await challengeStore.TryConsumeAsync(stored.Id, now, cancellationToken))
            return AuthenticationFailed();

        await lockoutManager.ResetAccessFailedCountAsync(user);
        var token = await sessionIssuer.IssueAsync(user, cancellationToken);
        return new Result<TUser, Token>(user, token);
    }

    protected static Result<TUser, Token> AuthenticationFailed() =>
        new(ResultCode.BadRequest, Result.CreateErrors("AuthenticationFailed", "The code is incorrect or the sign-in attempt has expired."));
}
