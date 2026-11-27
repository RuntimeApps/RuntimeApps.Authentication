using Microsoft.AspNetCore.Http;

namespace RuntimeApps.Authentication.Features.TwoFactor.Contracts;

/// <summary>
/// Throttles second-factor completion requests before any database access. The built-in implementation is
/// in-process and per client IP, so it does not coordinate across several instances. Replace it by registering
/// your own implementation before <c>AddTwoFactor</c> when you need shared (for example distributed) limits.
/// The per-challenge attempt cap and Identity lockout apply regardless of this limiter.
/// </summary>
public interface ITwoFactorRequestLimiter {
    /// <summary>Returns false when the request must be rejected with 429 Too Many Requests.</summary>
    ValueTask<bool> IsAllowedAsync(HttpContext context, CancellationToken cancellationToken = default);
}
