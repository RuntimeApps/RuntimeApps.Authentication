using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Service {
    internal interface IRefreshTokenRequestLimiter {
        ValueTask<bool> IsAllowedAsync(HttpContext context, CancellationToken cancellationToken = default);
    }

    internal sealed class RefreshTokenRequestLimiter : IRefreshTokenRequestLimiter, IDisposable {
        private readonly PartitionedRateLimiter<HttpContext> _limiter;

        public RefreshTokenRequestLimiter(IOptions<RefreshTokenOptions> options) {
            var limit = options.Value.RefreshRequestsPerMinute;
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
            using var lease = await _limiter.AcquireAsync(context, 1, cancellationToken);
            return lease.IsAcquired;
        }

        public void Dispose() => _limiter.Dispose();
    }
}