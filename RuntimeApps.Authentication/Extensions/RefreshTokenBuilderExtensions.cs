using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
                .ValidateOnStart();

            builder.Services.TryAddSingleton(TimeProvider.System);
            builder.Services.TryAddScoped<IRefreshTokenService<TKey>, RefreshTokenService<TKey>>();
            return builder;
        }
    }
}