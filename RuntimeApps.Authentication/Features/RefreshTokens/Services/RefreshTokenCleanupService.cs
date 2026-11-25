using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
namespace RuntimeApps.Authentication.Features.RefreshTokens.Services {
    public sealed class RefreshTokenCleanupService<TKey>: IRefreshTokenCleanupService<TKey>
        where TKey : IEquatable<TKey> {
        private readonly IRefreshTokenStore<TKey> _store;
        private readonly RefreshTokenOptions _options;
        private readonly TimeProvider _timeProvider;

        public RefreshTokenCleanupService(
            IRefreshTokenStore<TKey> store,
            IOptions<RefreshTokenOptions> options,
            TimeProvider timeProvider) {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
            _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        }

        public async Task<int> CleanupAsync(CancellationToken cancellationToken = default) {
            if(_store is not IRefreshTokenCleanupStore<TKey> cleanupStore)
                throw new InvalidOperationException(
                    $"The registered refresh-token store '{_store.GetType().Name}' does not support cleanup. " +
                    $"Implement {nameof(IRefreshTokenCleanupStore<TKey>)} on it or use the EF Core store.");

            return await cleanupStore.DeleteInactiveAsync(
                _timeProvider.GetUtcNow(), _options.CleanupRetention, _options.CleanupBatchSize, cancellationToken);
        }
    }
}
