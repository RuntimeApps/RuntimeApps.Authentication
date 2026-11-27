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

    /// <summary>
    /// How long an accepted code is remembered to reject replay. Must cover the longest time a code stays valid:
    /// Identity accepts an authenticator code for about 150 seconds. Raise it for delivery methods with
    /// longer-lived codes. Default 10 minutes (minimum 3 minutes).
    /// </summary>
    public TimeSpan UsedCodeRetention { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>How long after expiry a login challenge row is kept before cleanup may delete it. Default 1 hour.</summary>
    public TimeSpan CleanupRetention { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Maximum rows one cleanup call deletes. Default 1000.</summary>
    public int CleanupBatchSize { get; set; } = 1000;

    /// <summary>
    /// What login does when a user has two-factor enabled but no enrolled method. The default,
    /// <see cref="TwoFactorNoMethodBehavior.RequireTwoFactor"/>, is fail-closed.
    /// </summary>
    public TwoFactorNoMethodBehavior NoEnrolledMethodBehavior { get; set; } = TwoFactorNoMethodBehavior.RequireTwoFactor;

    /// <summary>Second-factor completion requests accepted per minute from one client IP address. Default 10.</summary>
    public int CompleteRequestsPerMinute { get; set; } = 10;

    public void Validate() {
        if(string.IsNullOrWhiteSpace(Issuer) || Issuer.Length > 100 || Issuer.Contains(':') || Issuer.Any(char.IsControl))
            throw new InvalidOperationException("A two-factor issuer is required. It must be at most 100 characters and must not contain ':' or control characters.");
        if(ChallengeLifetime < TimeSpan.FromSeconds(30) || ChallengeLifetime > TimeSpan.FromMinutes(15))
            throw new InvalidOperationException("The two-factor challenge lifetime must be between 30 seconds and 15 minutes.");
        if(MaxAttemptsPerChallenge is < 1 or > 10)
            throw new InvalidOperationException("The two-factor attempt limit per challenge must be between 1 and 10.");
        if(MaxPendingChallengesPerUser is < 1 or > 20)
            throw new InvalidOperationException("The pending two-factor challenge limit per user must be between 1 and 20.");
        if(UsedCodeRetention < TimeSpan.FromMinutes(3) || UsedCodeRetention > TimeSpan.FromDays(1))
            throw new InvalidOperationException("The used-code retention must be between 3 minutes and 1 day.");
        if(CleanupRetention < TimeSpan.Zero || CleanupRetention > TimeSpan.FromDays(30))
            throw new InvalidOperationException("The two-factor cleanup retention must be between zero and 30 days.");
        if(!Enum.IsDefined(NoEnrolledMethodBehavior))
            throw new InvalidOperationException("The behavior for users without an enrolled two-factor method is not a valid value.");
        if(CompleteRequestsPerMinute is < 1 or > 1000)
            throw new InvalidOperationException("The two-factor completion request limit must be between 1 and 1000 per minute.");
        if(CleanupBatchSize is < 1 or > 10000)
            throw new InvalidOperationException("The two-factor cleanup batch size must be between 1 and 10000.");
    }
}
