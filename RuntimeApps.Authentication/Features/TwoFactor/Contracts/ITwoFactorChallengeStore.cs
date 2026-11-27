using RuntimeApps.Authentication.Features.TwoFactor.Models;

namespace RuntimeApps.Authentication.Features.TwoFactor.Contracts;

/// <summary>
/// Persistence contract for login challenges and the used-code ledger. State-changing methods must be atomic;
/// implementations must use conditional updates, transactions or unique constraints so that parallel
/// requests cannot exceed attempt limits, consume a challenge twice or accept the same code twice.
/// </summary>
public interface ITwoFactorChallengeStore<TKey> where TKey : IEquatable<TKey> {
    /// <summary>
    /// Stores a new pending challenge. In the same transaction, the user's oldest unexpired pending challenges
    /// are superseded so at most <paramref name="maxPendingPerUser"/> remain, including the new one.
    /// </summary>
    Task CreateAsync(TwoFactorChallenge<TKey> challenge, int maxPendingPerUser, CancellationToken cancellationToken = default);

    Task<TwoFactorChallenge<TKey>> FindByHandleHashAsync(string handleHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Counts one attempt before the code is checked. Succeeds only while the challenge is pending, unexpired and
    /// below <paramref name="maxAttempts"/>. The attempt is spent whether or not the code turns out to be correct.
    /// </summary>
    Task<bool> TryReserveAttemptAsync(TKey challengeId, int maxAttempts, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>Marks a pending, unexpired challenge as completed. Returns false if it was already consumed, superseded or expired.</summary>
    Task<bool> TryConsumeAsync(TKey challengeId, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records an accepted code. Returns false when the same user, method and code hash is already recorded
    /// and not yet expired, which means the code is being replayed.
    /// </summary>
    Task<bool> TryMarkCodeUsedAsync(TKey userId, string method, string codeHash, DateTimeOffset usedAt, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);
}
