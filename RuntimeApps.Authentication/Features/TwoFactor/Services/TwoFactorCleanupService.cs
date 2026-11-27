using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;

namespace RuntimeApps.Authentication.Features.TwoFactor.Services;

public sealed class TwoFactorCleanupService<TKey>(
    ITwoFactorChallengeStore<TKey> store,
    IOptions<TwoFactorOptions> options,
    TimeProvider timeProvider) : ITwoFactorCleanupService<TKey> where TKey : IEquatable<TKey> {
    public async Task<int> CleanupAsync(CancellationToken cancellationToken = default) {
        if(store is not ITwoFactorCleanupStore<TKey> cleanupStore)
            throw new InvalidOperationException(
                $"The registered two-factor store '{store.GetType().Name}' does not support cleanup. " +
                $"Implement {nameof(ITwoFactorCleanupStore<TKey>)} on it or use the EF Core store.");
        var value = options.Value;
        return await cleanupStore.DeleteExpiredAsync(timeProvider.GetUtcNow(), value.CleanupRetention, value.CleanupBatchSize, cancellationToken);
    }
}
