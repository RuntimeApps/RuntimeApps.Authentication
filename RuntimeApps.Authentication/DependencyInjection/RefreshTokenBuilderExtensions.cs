using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Features.RefreshTokens.Services;
namespace RuntimeApps.Authentication.DependencyInjection {
    public static class RefreshTokenBuilderExtensions {
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddRefreshToken<TUser, TRole, TKey>(
            this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, IConfiguration configuration,
            Action<RefreshTokenOptions> configure = null)
            where TUser : Microsoft.AspNetCore.Identity.IdentityUser<TKey>, new()
            where TRole : Microsoft.AspNetCore.Identity.IdentityRole<TKey>
            where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(configuration);
            var configuredOptions = builder.Services.AddOptions<RefreshTokenOptions>()
                .Bind(configuration.GetSection(RefreshTokenOptions.SectionName));
            if (configure != null) configuredOptions.Configure(configure);
            AddServices(builder, configuredOptions);
            return builder;
        }
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

            var configuredOptions = builder.Services.AddOptions<RefreshTokenOptions>();
            configuredOptions.Configure(configure ?? (_ => { }));
            AddServices(builder, configuredOptions);
            return builder;
        }

        private static void AddServices<TUser, TRole, TKey>(RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, OptionsBuilder<RefreshTokenOptions> configuredOptions)
            where TUser : Microsoft.AspNetCore.Identity.IdentityUser<TKey>, new()
            where TRole : Microsoft.AspNetCore.Identity.IdentityRole<TKey>
            where TKey : IEquatable<TKey> {
            configuredOptions
                .Validate(options => options.TokenLifetime > TimeSpan.Zero,
                    "Refresh-token lifetime must be greater than zero.")
                .Validate(options => options.AbsoluteSessionLifetime >= options.TokenLifetime,
                    "Absolute session lifetime must be greater than or equal to the refresh-token lifetime.")
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
        }
    }
}
