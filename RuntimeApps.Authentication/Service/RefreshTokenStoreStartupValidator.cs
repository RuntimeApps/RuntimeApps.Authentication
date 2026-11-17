using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Service {
    internal sealed class RefreshTokenStoreStartupValidator<TKey> : IHostedService
        where TKey : IEquatable<TKey> {
        private readonly IServiceScopeFactory _scopeFactory;

        public RefreshTokenStoreStartupValidator(IServiceScopeFactory scopeFactory) {
            _scopeFactory = scopeFactory;
        }

        public async Task StartAsync(CancellationToken cancellationToken) {
            await using var scope = _scopeFactory.CreateAsyncScope();
            _ = scope.ServiceProvider.GetRequiredService<IRefreshTokenStore<TKey>>();
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}