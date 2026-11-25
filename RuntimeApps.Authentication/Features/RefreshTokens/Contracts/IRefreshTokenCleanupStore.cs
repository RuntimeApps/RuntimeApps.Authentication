namespace RuntimeApps.Authentication.Features.RefreshTokens.Contracts {
    /// <summary>
    /// Optional capability of an <see cref="IRefreshTokenStore{TKey}"/>: permanently removes refresh-token
    /// records that can no longer be used. Existing custom stores are unaffected until they implement it.
    /// </summary>
    public interface IRefreshTokenCleanupStore<TKey>
        where TKey : IEquatable<TKey> {
        /// <summary>
        /// Deletes at most <paramref name="batchSize"/> inactive records and returns how many were deleted.
        /// A record is inactive when it was revoked (or rotated) more than <paramref name="retention"/> before
        /// <paramref name="now"/>, or it was never revoked and expired more than <paramref name="retention"/>
        /// before <paramref name="now"/>. Implementations must never delete a record that is neither revoked
        /// nor expired, and must reject a negative <paramref name="retention"/>.
        /// </summary>
        Task<int> DeleteInactiveAsync(
            DateTimeOffset now,
            TimeSpan retention,
            int batchSize,
            CancellationToken cancellationToken = default);
    }
}
