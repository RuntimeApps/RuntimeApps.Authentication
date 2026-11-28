using System.Globalization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Features.TwoFactor.Services;

public class TwoFactorManagementService<TUser, TKey>(
    IEnumerable<ITwoFactorMethod<TUser>> methods,
    IUserTwoFactorManager<TUser> twoFactorManager,
    IUserLockoutManager<TUser> lockoutManager,
    TwoFactorReauthenticator<TUser> reauthenticator,
    ITwoFactorChallengeStore<TKey> challengeStore,
    IOptions<TwoFactorOptions> options,
    TimeProvider timeProvider) : ITwoFactorManagementService<TUser>
    where TUser : IdentityUser<TKey>
    where TKey : IEquatable<TKey> {
    public virtual async Task<TwoFactorStatus> GetStatusAsync(TUser user, CancellationToken cancellationToken = default) {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();
        var enabled = await twoFactorManager.GetTwoFactorEnabledAsync(user);
        var statuses = new List<TwoFactorMethodStatus>();
        foreach(var method in methods) {
            cancellationToken.ThrowIfCancellationRequested();
            statuses.Add(new TwoFactorMethodStatus(method.Name, method.IsDeliveryBased, await method.IsEnrolledAsync(user, cancellationToken)));
        }
        return new TwoFactorStatus(enabled, statuses);
    }

    public virtual async Task<Result<TwoFactorEnrollmentInfo>> BeginSetupAsync(TUser user, string method, TwoFactorReauthenticationModel request, CancellationToken cancellationToken = default) {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();
        var selected = FindMethod(method);
        if(selected == null)
            return Failure<TwoFactorEnrollmentInfo>(ResultCode.BadRequest, "InvalidTwoFactorMethod", "The two-factor method is not available.");

        if(await lockoutManager.IsLockedOutAsync(user))
            return Failure<TwoFactorEnrollmentInfo>(ResultCode.Locked, "AccountLocked", "The account is temporarily locked.");
        if(!await reauthenticator.IsReauthenticatedAsync(user, request, cancellationToken))
            return Failure<TwoFactorEnrollmentInfo>(ResultCode.Forbidden, "ReauthenticationRequired", "Re-authentication is required to set up two-factor authentication.");

        // Once two-factor is on, a password alone must not be enough to add or replace a method.
        if(await twoFactorManager.GetTwoFactorEnabledAsync(user))
            return Failure<TwoFactorEnrollmentInfo>(ResultCode.Conflict, "TwoFactorAlreadyEnabled", "Two-factor authentication is already enabled. Disable it before setting it up again.");

        cancellationToken.ThrowIfCancellationRequested();
        return new Result<TwoFactorEnrollmentInfo>(await selected.BeginEnrollmentAsync(user, cancellationToken));
    }

    /// <remarks>
    /// Order: the code is checked first, then recorded as used, and only then is anything changed. Clearing the other
    /// methods happens before the flag is turned on, so there is never a moment with the flag on and a stale secret.
    /// </remarks>
    public virtual async Task<Result<TwoFactorStatus>> ConfirmSetupAsync(TUser user, string method, string code, CancellationToken cancellationToken = default) {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();
        var selected = FindMethod(method);
        if(selected == null)
            return Failure<TwoFactorStatus>(ResultCode.BadRequest, "InvalidTwoFactorMethod", "The two-factor method is not available.");
        if(await lockoutManager.IsLockedOutAsync(user))
            return Failure<TwoFactorStatus>(ResultCode.Locked, "AccountLocked", "The account is temporarily locked.");
        if(await twoFactorManager.GetTwoFactorEnabledAsync(user))
            return Failure<TwoFactorStatus>(ResultCode.Conflict, "TwoFactorAlreadyEnabled", "Two-factor authentication is already enabled.");

        if(!await AcceptCodeAsync(user, selected, code, confirmEnrollment: true, cancellationToken))
            return Failure<TwoFactorStatus>(ResultCode.BadRequest, "InvalidCode", "The code is incorrect or has already been used.");

        // Two-factor was off, so no other method is enrolled and anything they stored is an unconfirmed leftover.
        foreach(var other in methods.Where(item => !ReferenceEquals(item, selected)))
            await other.ClearEnrollmentAsync(user, cancellationToken);
        var enabled = await twoFactorManager.SetTwoFactorEnabledAsync(user, true);
        if(!enabled.Succeeded)
            throw new InvalidOperationException("Two-factor authentication could not be enabled.");
        return new Result<TwoFactorStatus>(await GetStatusAsync(user, cancellationToken));
    }

    /// <remarks>
    /// The flag is turned off before any method clears its data: if clearing fails the account is merely left with an
    /// unused secret (setup rotates it), whereas clearing first could leave two-factor on with a secret nobody has.
    /// </remarks>
    public virtual async Task<Result<TwoFactorStatus>> DisableAsync(TUser user, TwoFactorDisableModel request, CancellationToken cancellationToken = default) {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();
        if(request == null)
            return Failure<TwoFactorStatus>(ResultCode.BadRequest, "InvalidTwoFactorRequest", "A method and a code are required.");
        var selected = FindMethod(request.Method);
        if(selected == null)
            return Failure<TwoFactorStatus>(ResultCode.BadRequest, "InvalidTwoFactorMethod", "The two-factor method is not available.");
        if(await lockoutManager.IsLockedOutAsync(user))
            return Failure<TwoFactorStatus>(ResultCode.Locked, "AccountLocked", "The account is temporarily locked.");
        if(!await reauthenticator.IsReauthenticatedAsync(user, request, cancellationToken))
            return Failure<TwoFactorStatus>(ResultCode.Forbidden, "ReauthenticationRequired", "Re-authentication is required to disable two-factor authentication.");
        if(!await twoFactorManager.GetTwoFactorEnabledAsync(user))
            return Failure<TwoFactorStatus>(ResultCode.Conflict, "TwoFactorNotEnabled", "Two-factor authentication is not enabled.");

        // The code must come from a method the user can really answer with.
        if(!await selected.IsEnrolledAsync(user, cancellationToken) ||
           !await AcceptCodeAsync(user, selected, request.Code, confirmEnrollment: false, cancellationToken))
            return Failure<TwoFactorStatus>(ResultCode.Forbidden, "InvalidCode", "The code is incorrect or has already been used.");

        var disabled = await twoFactorManager.SetTwoFactorEnabledAsync(user, false);
        if(!disabled.Succeeded)
            throw new InvalidOperationException("Two-factor authentication could not be disabled.");
        foreach(var method in methods)
            await method.ClearEnrollmentAsync(user, cancellationToken);
        return new Result<TwoFactorStatus>(await GetStatusAsync(user, cancellationToken));
    }

    /// <summary>
    /// Validates a submitted code for <paramref name="selected"/> and records it as used. Wrong, malformed-but-verified
    /// and replayed codes count toward lockout. Returns false for any rejected code.
    /// </summary>
    protected async Task<bool> AcceptCodeAsync(TUser user, ITwoFactorMethod<TUser> selected, string code, bool confirmEnrollment, CancellationToken cancellationToken) {
        var normalized = string.IsNullOrWhiteSpace(code) ? null : selected.NormalizeCode(code);
        if(normalized == null)
            return false;

        var valid = confirmEnrollment
            ? await selected.ConfirmEnrollmentAsync(user, normalized, cancellationToken)
            : await selected.VerifyAsync(user, normalized, cancellationToken);
        if(!valid) {
            await lockoutManager.AccessFailedAsync(user);
            return false;
        }

        // Nothing is recorded yet, so honoring cancellation here cannot burn a valid code.
        cancellationToken.ThrowIfCancellationRequested();
        var now = timeProvider.GetUtcNow();
        var hash = TwoFactorCodeHash.Compute(Convert.ToString(user.Id, CultureInfo.InvariantCulture), selected.Name, normalized);
        if(!await challengeStore.TryMarkCodeUsedAsync(user.Id, selected.Name, hash, now, now + options.Value.UsedCodeRetention, cancellationToken)) {
            // A correct code that was already accepted is a replay, so it counts like a wrong code.
            await lockoutManager.AccessFailedAsync(user);
            return false;
        }
        return true;
    }

    protected ITwoFactorMethod<TUser> FindMethod(string name) =>
        string.IsNullOrWhiteSpace(name) ? null : methods.FirstOrDefault(item => string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase));

    protected static Result<T> Failure<T>(ResultCode code, string errorCode, string description) =>
        new(code, Result.CreateErrors(errorCode, description));
}
