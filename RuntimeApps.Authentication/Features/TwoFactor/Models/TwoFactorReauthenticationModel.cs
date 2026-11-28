namespace RuntimeApps.Authentication.Features.TwoFactor.Models;

/// <summary>
/// Fresh proof of control of the account, required before two-factor setup changes: the current password,
/// or a fresh token from a provider that is already linked to the account.
/// </summary>
public class TwoFactorReauthenticationModel {
    /// <summary>Current password. Accepted when the account has a password.</summary>
    public string CurrentPassword { get; set; }

    /// <summary>Provider of an already-linked identity used for re-authentication.</summary>
    public string ReauthenticationProvider { get; set; }

    /// <summary>Fresh token from <see cref="ReauthenticationProvider"/>.</summary>
    public string ReauthenticationToken { get; set; }
}
