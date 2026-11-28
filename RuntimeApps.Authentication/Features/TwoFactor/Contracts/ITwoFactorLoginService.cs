using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Features.TwoFactor.Contracts;

/// <summary>
/// Second-factor step of login. <see cref="BeginAsync"/> runs after the first factor (password or external
/// provider) succeeded; <see cref="CompleteAsync"/> turns a challenge plus a valid code into a session.
/// </summary>
/// <remarks>
/// Identity APIs underneath do not accept cancellation tokens. Implementations check the token before
/// starting and let an operation already started finish so persisted state is not reported as cancelled.
/// </remarks>
public interface ITwoFactorLoginService<TUser> where TUser : class {
    /// <summary>
    /// Creates a pending challenge for a user who passed the first factor and lists their enrolled methods.
    /// Never issues a session.
    /// </summary>
    Task<TwoFactorLoginStart> BeginAsync(TUser user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Like <see cref="BeginAsync"/>, for a user who passed an external provider login. Applies
    /// <c>TwoFactorOptions.ExternalLoginPolicy</c>: the result allows sign-in when the provider is trusted or the user
    /// has two-factor disabled, and otherwise carries a challenge. Never issues a session.
    /// </summary>
    Task<TwoFactorLoginStart> BeginExternalAsync(TUser user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies the code for the challenge and, only on success, issues the authentication session.
    /// Every failure (unknown, expired, used or locked challenge, wrong or replayed code, ineligible account,
    /// method not enrolled) returns the same non-succeeded result so callers cannot tell the reasons apart.
    /// Unexpected infrastructure failures throw instead of being reported as a failed code.
    /// </summary>
    Task<Result<TUser, Token>> CompleteAsync(string challenge, string method, string code, CancellationToken cancellationToken = default);
}
