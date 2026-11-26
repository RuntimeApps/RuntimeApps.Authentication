namespace RuntimeApps.Authentication.Features.RefreshTokens.Contracts {
    /// <summary>
    /// Removes expired and revoked refresh-token records once they are older than the configured retention.
    /// Scheduling is the application's responsibility; the library never runs cleanup by itself.
    /// </summary>
    public interface IRefreshTokenCleanupService<TKey>
        where TKey : IEquatable<TKey> {
        /// <summary>
        /// Deletes at most <c>RefreshTokenOptions.CleanupBatchSize</c> records and returns the number deleted.
        /// Call it repeatedly until it returns less than the batch size (or zero) to clear a backlog.
        /// </summary>
        /// <exception cref="InvalidOperationException">The registered store does not support cleanup.</exception>
        Task<int> CleanupAsync(CancellationToken cancellationToken = default);
    }
}
