namespace RuntimeApps.Authentication.Features.TwoFactor.Models;

/// <summary>Whether signing in through an external provider also requires the local second factor.</summary>
public enum TwoFactorExternalLoginPolicy {
    /// <summary>
    /// A user who has two-factor enabled must also answer a challenge after an external login. Safe default: a
    /// compromised provider account, or a provider login linked by trusted email, cannot enter a protected account alone.
    /// </summary>
    RequireWhenEnabled = 0,

    /// <summary>
    /// The provider is trusted to have authenticated the user, so the local second step is skipped for external logins.
    /// Whoever controls the provider account can then sign in without the local second factor.
    /// </summary>
    TrustProvider = 1
}
