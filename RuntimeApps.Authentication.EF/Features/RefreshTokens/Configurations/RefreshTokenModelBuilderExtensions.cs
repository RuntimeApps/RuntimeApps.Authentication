using Microsoft.EntityFrameworkCore;
namespace RuntimeApps.Authentication.EF.Features.RefreshTokens.Configurations {
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
