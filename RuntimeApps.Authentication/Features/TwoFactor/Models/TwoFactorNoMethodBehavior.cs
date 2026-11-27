namespace RuntimeApps.Authentication.Features.TwoFactor.Models;

/// <summary>Login behavior for a user whose two-factor flag is on but who has no enrolled method.</summary>
public enum TwoFactorNoMethodBehavior {
    /// <summary>
    /// Fail closed: login returns the second-step response with an empty method list, so the user cannot
    /// sign in until an administrator resets two-factor for the account. Safe default.
    /// </summary>
    RequireTwoFactor = 0,

    /// <summary>
    /// Sign the user in with the password alone. This weakens two-factor for any account whose methods were
    /// removed or never enrolled; choose it only when every user must be able to sign in regardless.
    /// </summary>
    AllowSignIn = 1
}
