using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.EF.Model;

namespace RuntimeApps.Authentication.EF.Extensions {
    public static class VerificationRequestModelBuilderExtensions {
        /// <summary>Adds the verification request and delivery-rate-limit entities to the consumer DbContext.</summary>
        public static ModelBuilder AddVerificationRequestEntity<TKey>(this ModelBuilder modelBuilder)
            where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(modelBuilder);
            modelBuilder.ApplyConfiguration(new VerificationRequestConfiguration<TKey>());
            modelBuilder.ApplyConfiguration(new VerificationSendConfiguration());
            return modelBuilder;
        }
    }
}