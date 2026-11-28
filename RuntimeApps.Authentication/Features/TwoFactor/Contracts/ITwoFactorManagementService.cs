using RuntimeApps.Authentication.Features.TwoFactor.Models;

namespace RuntimeApps.Authentication.Features.TwoFactor.Contracts;

/// <summary>
/// Two-factor management for the signed-in account: status, setup, confirmation and disabling. The service
/// owns the security rules (re-authentication, lockout counting, replay protection); the HTTP layer only maps
/// requests and results.
/// </summary>
public interface ITwoFactorManagementService<TUser> where TUser : class {
    /// <summary>Returns whether two-factor is on and which registered methods the user has enrolled. Contains no secrets.</summary>
    Task<TwoFactorStatus> GetStatusAsync(TUser user, CancellationToken cancellationToken = default);
}
