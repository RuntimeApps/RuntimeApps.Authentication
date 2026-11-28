using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Features.TwoFactor.Contracts;

/// <summary>
/// Two-factor management for the signed-in account: status, setup, confirmation and disabling. The service
/// owns the security rules (re-authentication, lockout counting, replay protection); the HTTP layer only maps
/// requests and results.
/// </summary>
public interface ITwoFactorManagementService<TUser> where TUser : class {
    /// <summary>Returns whether two-factor is on and which registered methods the user has enrolled. Contains no secrets.</summary>
    Task<TwoFactorStatus> GetStatusAsync(TUser user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Starts enrollment of <paramref name="method"/> and returns the data the client needs (for the authenticator, the
    /// shared key and otpauth URI). Requires re-authentication and is refused while two-factor is already enabled, so
    /// only a first enrollment can happen without a current code. The result contains secrets and must not be cached.
    /// Failures: BadRequest (unknown method), Forbidden (re-authentication failed), Conflict (already enabled).
    /// </summary>
    Task<Result<TwoFactorEnrollmentInfo>> BeginSetupAsync(TUser user, string method, TwoFactorReauthenticationModel request, CancellationToken cancellationToken = default);
}
