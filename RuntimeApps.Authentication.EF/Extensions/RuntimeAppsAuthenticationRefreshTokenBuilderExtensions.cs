using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RuntimeApps.Authentication.EF.Store;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.EF.Extensions {
    public static class RuntimeAppsAuthenticationRefreshTokenBuilderExtensions {
        /// <summary>Registers the EF-backed refresh-token store for an Identity DbContext.</summary>
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddEfRefreshTokenStore<TDbContext, TUser, TRole, TKey>(
            this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder)
            where TDbContext : DbContext
            where TUser : IdentityUser<TKey>, new()
            where TRole : IdentityRole<TKey>
            where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(builder);
            builder.Services.TryAddScoped<IRefreshTokenStore<TKey>, EfRefreshTokenStore<TDbContext, TKey>>();
            return builder;
        }
    }
}