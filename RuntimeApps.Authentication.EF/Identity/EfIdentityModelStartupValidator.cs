using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
namespace RuntimeApps.Authentication.EF.Identity {
    /// <summary>
    /// Fails fast when the DbContext used with <c>AddEfStores</c> does not map the default Identity entities.
    /// </summary>
    internal sealed class EfIdentityModelStartupValidator<TDbContext, TUser, TRole, TKey>: IHostedService
        where TDbContext : DbContext
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey> {
        private readonly IServiceScopeFactory _scopeFactory;

        public EfIdentityModelStartupValidator(IServiceScopeFactory scopeFactory) {
            _scopeFactory = scopeFactory;
        }

        public Task StartAsync(CancellationToken cancellationToken) {
            using var scope = _scopeFactory.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<TDbContext>();
            var missing = GetMissingEntityTypes(dbContext.Model).ToList();
            if(missing.Count > 0)
                throw new InvalidOperationException(
                    $"{typeof(TDbContext).Name} does not map the Identity entities required by AddEfStores: " +
                    $"{string.Join(", ", missing)}. Derive from IdentityDbContext<{typeof(TUser).Name}, {typeof(TRole).Name}, {typeof(TKey).Name}> " +
                    "or map these entities in OnModelCreating. Custom claim, login, token or user-role entity types are not supported by the built-in stores.");
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        internal static IEnumerable<string> GetMissingEntityTypes(Microsoft.EntityFrameworkCore.Metadata.IModel model) {
            foreach(var type in new[] {
                typeof(TUser), typeof(TRole), typeof(IdentityUserClaim<TKey>), typeof(IdentityUserRole<TKey>),
                typeof(IdentityUserLogin<TKey>), typeof(IdentityUserToken<TKey>), typeof(IdentityRoleClaim<TKey>)
            }) {
                if(model.FindEntityType(type) == null)
                    yield return type.Name;
            }
        }
    }
}
