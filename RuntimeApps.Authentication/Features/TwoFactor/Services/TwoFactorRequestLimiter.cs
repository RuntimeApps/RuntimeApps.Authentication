using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;

namespace RuntimeApps.Authentication.Features.TwoFactor.Services;

/// <summary>Fixed-window, per-IP limiter held in process memory.</summary>
public sealed class TwoFactorRequestLimiter : ITwoFactorRequestLimiter, IDisposable {
    private readonly PartitionedRateLimiter<HttpContext> _limiter;

    public TwoFactorRequestLimiter(IOptions<TwoFactorOptions> options) {
        var limit = options.Value.CompleteRequestsPerMinute;
        _limiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
            RateLimitPartition.GetFixedWindowLimiter(
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions {
                    PermitLimit = limit,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                    AutoReplenishment = true
                }));
    }

    public async ValueTask<bool> IsAllowedAsync(HttpContext context, CancellationToken cancellationToken = default) {
        ArgumentNullException.ThrowIfNull(context);
        using var lease = await _limiter.AcquireAsync(context, 1, cancellationToken);
        return lease.IsAcquired;
    }

    public void Dispose() => _limiter.Dispose();
}
