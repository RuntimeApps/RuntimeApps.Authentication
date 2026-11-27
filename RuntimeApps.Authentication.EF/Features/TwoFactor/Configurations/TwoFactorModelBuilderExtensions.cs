using Microsoft.EntityFrameworkCore;

namespace RuntimeApps.Authentication.EF.Features.TwoFactor.Configurations;

public static class TwoFactorModelBuilderExtensions {
    /// <summary>Adds the two-factor challenge and used-code ledger entities to the consumer DbContext.</summary>
    public static ModelBuilder AddTwoFactorChallengeEntity<TKey>(this ModelBuilder modelBuilder)
        where TKey : IEquatable<TKey> {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        modelBuilder.ApplyConfiguration(new TwoFactorChallengeConfiguration<TKey>());
        modelBuilder.ApplyConfiguration(new TwoFactorUsedCodeConfiguration<TKey>());
        return modelBuilder;
    }
}
