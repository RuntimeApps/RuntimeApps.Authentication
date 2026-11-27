using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.Verification.Services;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Features.TwoFactor.Services;

public class TwoFactorLoginService<TUser, TKey>(
    ITwoFactorChallengeStore<TKey> challengeStore,
    IEnumerable<ITwoFactorMethod<TUser>> methods,
    IOptions<TwoFactorOptions> options,
    TimeProvider timeProvider) : ITwoFactorLoginService<TUser>
    where TUser : IdentityUser<TKey>
    where TKey : IEquatable<TKey> {
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

    public virtual Task<Result<TUser, Token>> CompleteAsync(string challenge, string method, string code, CancellationToken cancellationToken = default) =>
        // Completion is added in a later commit. Until then every attempt is rejected, which is the safe default.
        Task.FromResult(AuthenticationFailed());

    protected static Result<TUser, Token> AuthenticationFailed() =>
        new(ResultCode.BadRequest, Result.CreateErrors("AuthenticationFailed", "The code is incorrect or the sign-in attempt has expired."));
}
