namespace RuntimeApps.Authentication.Features.TwoFactor.Models;

/// <summary>
/// Persisted state of a login second-factor challenge. The raw public handle must never be stored;
/// only its SHA-256 hash (see <c>VerificationHandle</c>) is persisted.
/// </summary>
public class TwoFactorChallenge<TKey> where TKey : IEquatable<TKey> {
    public TKey Id { get; set; }
    public TKey UserId { get; set; }
    public string HandleHash { get; set; }
    public TwoFactorChallengeStatus Status { get; set; }

    /// <summary>
    /// Attempts reserved so far, counted before the code is checked so parallel guesses cannot exceed the limit.
    /// A challenge whose attempts reached the limit is locked even though its status is still <see cref="TwoFactorChallengeStatus.Pending"/>.
    /// </summary>
    public int Attempts { get; set; }

    /// <summary>Codes delivered for this challenge (email/SMS methods).</summary>
    public int SendCount { get; set; }
    public DateTimeOffset? LastSentAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
}
