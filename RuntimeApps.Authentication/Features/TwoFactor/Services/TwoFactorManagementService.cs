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
    where TUser : class
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

        if(!await reauthenticator.IsReauthenticatedAsync(user, request, cancellationToken))
            return Failure<TwoFactorEnrollmentInfo>(ResultCode.Forbidden, "ReauthenticationRequired", "Re-authentication is required to set up two-factor authentication.");

        // Once two-factor is on, a password alone must not be enough to add or replace a method.
        if(await twoFactorManager.GetTwoFactorEnabledAsync(user))
            return Failure<TwoFactorEnrollmentInfo>(ResultCode.Conflict, "TwoFactorAlreadyEnabled", "Two-factor authentication is already enabled. Disable it before setting it up again.");

        cancellationToken.ThrowIfCancellationRequested();
        return new Result<TwoFactorEnrollmentInfo>(await selected.BeginEnrollmentAsync(user, cancellationToken));
    }

    protected ITwoFactorMethod<TUser> FindMethod(string name) =>
        string.IsNullOrWhiteSpace(name) ? null : methods.FirstOrDefault(item => string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase));

    protected static Result<T> Failure<T>(ResultCode code, string errorCode, string description) =>
        new(code, Result.CreateErrors(errorCode, description));
}
