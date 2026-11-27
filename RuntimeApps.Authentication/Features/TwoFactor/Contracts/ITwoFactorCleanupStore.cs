namespace RuntimeApps.Authentication.Features.TwoFactor.Contracts;

/// <summary>
/// Optional capability of an <see cref="ITwoFactorChallengeStore{TKey}"/>: permanently removes challenges and
/// ledger entries that can no longer matter. Custom stores are unaffected until they implement it.
/// </summary>
public interface ITwoFactorCleanupStore<TKey> where TKey : IEquatable<TKey> {
    /// <summary>
    /// Deletes at most <paramref name="batchSize"/> rows in total and returns how many were deleted.
    /// Ledger entries are deleted once expired. Challenges are deleted once they expired more than
    /// <paramref name="retention"/> before <paramref name="now"/>. Never deletes a row that is still usable,
    /// and must reject a negative <paramref name="retention"/>.
    /// </summary>
    Task<int> DeleteExpiredAsync(DateTimeOffset now, TimeSpan retention, int batchSize, CancellationToken cancellationToken = default);
}
