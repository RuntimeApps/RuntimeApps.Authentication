using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Features.RefreshTokens.Services;
namespace RuntimeApps.Authentication.DependencyInjection {
    public static class RefreshTokenBuilderExtensions {
        /// <summary>
        /// Enables refresh-token management. A store must also be registered, either by the EF
        /// integration package or by the application. Without this call, refresh-token services
        /// are not registered and the existing authentication flow is unchanged.
        /// </summary>
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddRefreshToken<TUser, TRole, TKey>(
            this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder,
            Action<RefreshTokenOptions> configure = null)
            where TUser : Microsoft.AspNetCore.Identity.IdentityUser<TKey>, new()
            where TRole : Microsoft.AspNetCore.Identity.IdentityRole<TKey>
            where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(builder);

            builder.Services.AddOptions<RefreshTokenOptions>()
                .Configure(configure ?? (_ => { }))
                .Validate(options => options.TokenLifetime > TimeSpan.Zero,
                    "Refresh-token lifetime must be greater than zero.")
                .Validate(options => options.RefreshRequestsPerMinute > 0,
                    "Refresh request rate limit must be greater than zero.")
                .Validate(options => !string.IsNullOrWhiteSpace(options.CookieName) &&
                    !string.IsNullOrWhiteSpace(options.CookiePath),
                    "Refresh-token cookie name and path are required.")
                .Validate(options => !string.IsNullOrWhiteSpace(options.CookieName) &&
                    (!options.CookieName.StartsWith("__Host-", StringComparison.Ordinal) ||
                     (options.CookieSecure && options.CookiePath == "/")),
                    "Cookies using the __Host- prefix require Secure and the root path.")
                .Validate(options => options.CookieSameSite != Microsoft.AspNetCore.Http.SameSiteMode.None || options.CookieSecure,
                    "SameSite=None cookies must also be Secure.")
                .Validate(options => options.AllowedOrigins != null && options.AllowedOrigins.All(origin =>
                    Uri.TryCreate(origin, UriKind.Absolute, out var uri) &&
                    (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps) &&
                    string.IsNullOrEmpty(uri.UserInfo) && uri.AbsolutePath == "/" &&
                    string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment)),
                    "Allowed origins must be absolute HTTP or HTTPS origins without a path, query, or fragment.")
                .ValidateOnStart();

            builder.Services.TryAddSingleton(TimeProvider.System);
            builder.Services.TryAddScoped<IRefreshTokenService<TKey>, RefreshTokenService<TKey>>();
            builder.Services.TryAddSingleton<IRefreshTokenRequestLimiter, RefreshTokenRequestLimiter>();
            builder.Services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IHostedService, RefreshTokenStoreStartupValidator<TKey>>());
            return builder;
        }
    }
}
