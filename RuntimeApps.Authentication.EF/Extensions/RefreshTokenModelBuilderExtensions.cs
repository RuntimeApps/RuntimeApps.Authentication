using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.EF.Model;

namespace RuntimeApps.Authentication.EF.Extensions {
    public static class RefreshTokenModelBuilderExtensions {
        /// <summary>Adds the refresh-token entity to the consumer application's DbContext model.</summary>
        public static ModelBuilder AddRefreshTokenEntity<TKey>(this ModelBuilder modelBuilder)
            where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(modelBuilder);
            modelBuilder.ApplyConfiguration(new RefreshTokenConfiguration<TKey>());
            return modelBuilder;
        }
    }
}