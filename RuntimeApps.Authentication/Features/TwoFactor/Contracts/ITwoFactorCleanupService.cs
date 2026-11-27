namespace RuntimeApps.Authentication.Features.TwoFactor.Contracts;

/// <summary>
/// Removes expired two-factor challenges and used-code ledger entries. Scheduling is the application's
/// responsibility; the library never runs cleanup by itself.
/// </summary>
public interface ITwoFactorCleanupService<TKey> where TKey : IEquatable<TKey> {
    /// <summary>
    /// Deletes at most <c>TwoFactorOptions.CleanupBatchSize</c> rows and returns the number deleted.
    /// Call it repeatedly until it returns less than the batch size to clear a backlog.
    /// </summary>
    /// <exception cref="InvalidOperationException">The registered store does not support cleanup.</exception>
    Task<int> CleanupAsync(CancellationToken cancellationToken = default);
}
