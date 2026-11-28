namespace RuntimeApps.Authentication.Features.TwoFactor.Models;

/// <summary>One registered second-factor method and whether the current user has enrolled it.</summary>
/// <param name="Name">Method name used in routes, for example "authenticator".</param>
/// <param name="RequiresSend">True when the code is delivered (email, SMS) and must be requested first.</param>
/// <param name="Enrolled">True when the user can currently answer a login challenge with this method.</param>
public sealed record TwoFactorMethodStatus(string Name, bool RequiresSend, bool Enrolled);

/// <summary>The two-factor state of the signed-in account. Contains no secrets.</summary>
/// <param name="Enabled">True when logins require a second step.</param>
/// <param name="Methods">Every registered method with the user's enrollment state.</param>
public sealed record TwoFactorStatus(bool Enabled, IReadOnlyList<TwoFactorMethodStatus> Methods);
