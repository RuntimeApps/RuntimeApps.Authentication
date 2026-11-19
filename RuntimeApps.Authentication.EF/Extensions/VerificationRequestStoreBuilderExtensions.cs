using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RuntimeApps.Authentication.EF.Store;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.EF.Extensions {
    public static class VerificationRequestStoreBuilderExtensions {
        /// <summary>Registers the EF Core verification-request store.</summary>
        public static IServiceCollection AddVerificationRequestStore<TDbContext, TKey>(this IServiceCollection services)
            where TDbContext : DbContext
            where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(services);
            services.TryAddScoped<IVerificationRequestStore<TKey>, EfVerificationRequestStore<TDbContext, TKey>>();
            return services;
        }
    }
}