using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using RuntimeApps.Authentication.Features.TwoFactor.Models;

namespace RuntimeApps.Authentication.EF.Features.TwoFactor.Configurations;

public sealed class TwoFactorChallengeConfiguration<TKey> : IEntityTypeConfiguration<TwoFactorChallenge<TKey>>
    where TKey : IEquatable<TKey> {
    public void Configure(EntityTypeBuilder<TwoFactorChallenge<TKey>> builder) {
        builder.ToTable("AuthenticationTwoFactorChallenges");
        builder.HasKey(challenge => challenge.Id);
        builder.Property(challenge => challenge.Id).ValueGeneratedOnAdd();
        builder.Property(challenge => challenge.UserId).IsRequired();
        builder.Property(challenge => challenge.HandleHash).HasMaxLength(64).IsRequired();
        builder.Property(challenge => challenge.Status).HasConversion<string>().HasMaxLength(32).IsRequired();
        builder.Property(challenge => challenge.CreatedAt).HasConversion(new DateTimeOffsetToBinaryConverter());
        builder.Property(challenge => challenge.ExpiresAt).HasConversion(new DateTimeOffsetToBinaryConverter());
        builder.Property(challenge => challenge.LastSentAt).HasConversion(new DateTimeOffsetToBinaryConverter());
        builder.Property(challenge => challenge.CompletedAt).HasConversion(new DateTimeOffsetToBinaryConverter());
        builder.HasIndex(challenge => challenge.HandleHash).IsUnique();
        builder.HasIndex(challenge => new { challenge.UserId, challenge.Status, challenge.CreatedAt });
        builder.HasIndex(challenge => challenge.ExpiresAt);
    }
}
