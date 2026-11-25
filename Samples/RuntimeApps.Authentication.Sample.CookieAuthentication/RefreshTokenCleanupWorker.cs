using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;

namespace RuntimeApps.Authentication.Sample.CookieAuthentication;

/// <summary>
/// Example scheduler for refresh-token cleanup. The library never runs cleanup by itself: the application
/// decides when and how often. Each cleanup call deletes at most <c>CleanupBatchSize</c> records, so the
/// worker repeats the call until a batch comes back smaller than that. Running this on several instances at
/// once is safe; deletes are idempotent and only ever remove records that are already inactive.
/// </summary>
public sealed class RefreshTokenCleanupWorker(
    IServiceScopeFactory scopeFactory,
    ILogger<RefreshTokenCleanupWorker> logger): BackgroundService {
    private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan Interval = TimeSpan.FromHours(6);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken) {
        try {
            await Task.Delay(StartupDelay, stoppingToken);
            using var timer = new PeriodicTimer(Interval);
            do {
                await RunOnceAsync(stoppingToken);
            } while(await timer.WaitForNextTickAsync(stoppingToken));
        } catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested) {
            // Normal shutdown.
        }
    }

    private async Task RunOnceAsync(CancellationToken cancellationToken) {
        try {
            await using var scope = scopeFactory.CreateAsyncScope();
            var cleanup = scope.ServiceProvider.GetRequiredService<IRefreshTokenCleanupService<int>>();
            var batchSize = scope.ServiceProvider.GetRequiredService<IOptions<RefreshTokenOptions>>().Value.CleanupBatchSize;

            var total = 0;
            int deleted;
            do {
                deleted = await cleanup.CleanupAsync(cancellationToken);
                total += deleted;
            } while(deleted >= batchSize);

            logger.LogInformation("Refresh-token cleanup removed {Count} record(s).", total);
        } catch(OperationCanceledException) when(cancellationToken.IsCancellationRequested) {
            throw;
        } catch(Exception ex) {
            // A failed run must not stop the worker; the next interval tries again.
            logger.LogError(ex, "Refresh-token cleanup failed.");
        }
    }
}
