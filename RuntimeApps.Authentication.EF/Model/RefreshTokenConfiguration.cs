using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.EF.Model {
    public sealed class RefreshTokenConfiguration<TKey> : IEntityTypeConfiguration<RefreshToken<TKey>>
        where TKey : IEquatable<TKey> {
        public void Configure(EntityTypeBuilder<RefreshToken<TKey>> builder) {
            builder.ToTable("AuthenticationRefreshTokens");
            builder.HasKey(token => token.Id);
            // Store UTC DateTimeOffset values as binary ticks so expiry predicates are
            // supported consistently by relational providers such as SQLite.
            builder.Property(token => token.CreatedAt).HasConversion(new DateTimeOffsetToBinaryConverter());
            builder.Property(token => token.ExpiresAt).HasConversion(new DateTimeOffsetToBinaryConverter());
            builder.Property(token => token.RevokedAt).HasConversion(new DateTimeOffsetToBinaryConverter());
            builder.Property(token => token.TokenHash).HasMaxLength(64).IsRequired();
            builder.Property(token => token.SessionName).HasMaxLength(100);
            builder.HasIndex(token => token.TokenHash).IsUnique();
            builder.HasIndex(token => new { token.UserId, token.FamilyId });
            builder.HasIndex(token => new { token.FamilyId, token.RevokedAt });
            builder.HasIndex(token => token.ExpiresAt);
        }
    }
}