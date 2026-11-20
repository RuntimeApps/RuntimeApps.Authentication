using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.EF.Features.RefreshTokens.Stores;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
namespace RuntimeApps.Authentication.EF.DependencyInjection {
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
