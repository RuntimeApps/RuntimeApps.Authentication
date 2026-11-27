using RuntimeApps.Authentication.Features.TwoFactor.Models;

namespace RuntimeApps.Authentication.Features.TwoFactor.Contracts;

/// <summary>
/// A second-factor method (authenticator app, email code, SMS code, ...). A method only answers
/// "can this user use me" and "is this code valid for this user". The framework owns every
/// security-critical rule around it: attempt counting, lockout, replay protection, challenge
/// single-use, throttling and token issuance. Implementations must not duplicate those rules.
/// </summary>
/// <remarks>
/// Identity APIs underneath do not accept cancellation tokens, so implementations should check the
/// token before starting an operation and let an operation already started finish.
/// Implementations must never log codes, keys or other secrets.
/// </remarks>
public interface ITwoFactorMethod<TUser> where TUser : class {
    /// <summary>
    /// Stable, unique method name used in routes and responses (for example "authenticator", "email", "sms").
    /// Must match <c>^[a-z][a-z0-9_-]{0,31}$</c>. Names are compared case-insensitively.
    /// </summary>
    string Name { get; }

    /// <summary>True when the code is delivered to the user (email, SMS) and <see cref="SendChallengeAsync"/> must be called first.</summary>
    bool IsDeliveryBased { get; }

    /// <summary>True when the user can currently complete a login challenge with this method.</summary>
    Task<bool> IsEnrolledAsync(TUser user, CancellationToken cancellationToken);

    /// <summary>Starts enrollment and returns method-specific data for the client. Must fail if the user is already enrolled.</summary>
    Task<TwoFactorEnrollmentInfo> BeginEnrollmentAsync(TUser user, CancellationToken cancellationToken);

    /// <summary>Checks the code that proves enrollment. Does not enable two-factor; the framework does that on success.</summary>
    Task<bool> ConfirmEnrollmentAsync(TUser user, string code, CancellationToken cancellationToken);

    /// <summary>Delivers a fresh code to the user. Only called when <see cref="IsDeliveryBased"/> is true.</summary>
    Task SendChallengeAsync(TUser user, CancellationToken cancellationToken) =>
        throw new NotSupportedException($"The '{Name}' two-factor method does not deliver codes.");

    /// <summary>
    /// Checks a login code. Return false for any invalid, expired or malformed code; do not throw for bad input.
    /// Replay and attempt limits are enforced by the framework.
    /// </summary>
    Task<bool> VerifyAsync(TUser user, string code, CancellationToken cancellationToken);
}
