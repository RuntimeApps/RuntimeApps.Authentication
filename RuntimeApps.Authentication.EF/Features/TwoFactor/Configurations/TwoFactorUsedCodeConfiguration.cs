using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using RuntimeApps.Authentication.Features.TwoFactor.Models;

namespace RuntimeApps.Authentication.EF.Features.TwoFactor.Configurations;

public sealed class TwoFactorUsedCodeConfiguration<TKey> : IEntityTypeConfiguration<TwoFactorUsedCode<TKey>>
    where TKey : IEquatable<TKey> {
    public void Configure(EntityTypeBuilder<TwoFactorUsedCode<TKey>> builder) {
        builder.ToTable("AuthenticationTwoFactorUsedCodes");
        builder.HasKey(code => code.Id);
        builder.Property(code => code.Id).ValueGeneratedOnAdd();
        builder.Property(code => code.UserId).IsRequired();
        builder.Property(code => code.Method).HasMaxLength(32).IsRequired();
        builder.Property(code => code.CodeHash).HasMaxLength(64).IsRequired();
        builder.Property(code => code.UsedAt).HasConversion(new DateTimeOffsetToBinaryConverter());
        builder.Property(code => code.ExpiresAt).HasConversion(new DateTimeOffsetToBinaryConverter());
        // The unique index is the atomic replay guard: of two parallel submissions of the same code, one insert fails.
        builder.HasIndex(code => new { code.UserId, code.Method, code.CodeHash }).IsUnique();
        builder.HasIndex(code => code.ExpiresAt);
    }
}
