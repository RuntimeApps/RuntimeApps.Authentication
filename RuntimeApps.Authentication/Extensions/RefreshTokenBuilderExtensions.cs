using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;
using RuntimeApps.Authentication.Service;

namespace RuntimeApps.Authentication.Extensions {
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
                .Validate(options => !string.IsNullOrWhiteSpace(options.CookieName) &&
                    !string.IsNullOrWhiteSpace(options.CookiePath),
                    "Refresh-token cookie name and path are required.")
                .Validate(options => !options.CookieName.StartsWith("__Host-", StringComparison.Ordinal) ||
                    (options.CookieSecure && options.CookiePath == "/"),
                    "Cookies using the __Host- prefix require Secure and the root path.")
                .Validate(options => options.CookieSameSite != Microsoft.AspNetCore.Http.SameSiteMode.None || options.CookieSecure,
                    "SameSite=None cookies must also be Secure.")
                .ValidateOnStart();

            builder.Services.TryAddSingleton(TimeProvider.System);
            builder.Services.TryAddScoped<IRefreshTokenService<TKey>, RefreshTokenService<TKey>>();
            builder.Services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IHostedService, RefreshTokenStoreStartupValidator<TKey>>());
            return builder;
        }
    }
}