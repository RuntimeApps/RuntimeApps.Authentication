using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Identity.Contracts;

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
}
