namespace RuntimeApps.Authentication.Features.TwoFactor.Models;

/// <summary>Options for API-based two-factor authentication. Bound from <see cref="SectionName"/>.</summary>
public sealed class TwoFactorOptions {
    public const string SectionName = "Authentication:TwoFactor";

    /// <summary>
    /// Application name shown in authenticator apps next to the account name. Required. Must not contain ':'.
    /// </summary>
    public string Issuer { get; set; }

    /// <summary>How long a login challenge stays valid after the password step succeeds. Default 5 minutes.</summary>
    public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Wrong second-factor codes accepted per challenge before it is permanently invalidated. Default 5.</summary>
    public int MaxAttemptsPerChallenge { get; set; } = 5;

    /// <summary>Unconsumed login challenges kept per user. When exceeded, the oldest is superseded. Default 5.</summary>
    public int MaxPendingChallengesPerUser { get; set; } = 5;

    public void Validate() {
        if(string.IsNullOrWhiteSpace(Issuer) || Issuer.Length > 100 || Issuer.Contains(':') || Issuer.Any(char.IsControl))
            throw new InvalidOperationException("A two-factor issuer is required. It must be at most 100 characters and must not contain ':' or control characters.");
        if(ChallengeLifetime < TimeSpan.FromSeconds(30) || ChallengeLifetime > TimeSpan.FromMinutes(15))
            throw new InvalidOperationException("The two-factor challenge lifetime must be between 30 seconds and 15 minutes.");
        if(MaxAttemptsPerChallenge is < 1 or > 10)
            throw new InvalidOperationException("The two-factor attempt limit per challenge must be between 1 and 10.");
        if(MaxPendingChallengesPerUser is < 1 or > 20)
            throw new InvalidOperationException("The pending two-factor challenge limit per user must be between 1 and 20.");
    }
}
