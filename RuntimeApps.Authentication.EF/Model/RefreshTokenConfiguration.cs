using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.EF.Model {
    public sealed class RefreshTokenConfiguration<TKey> : IEntityTypeConfiguration<RefreshToken<TKey>>
        where TKey : IEquatable<TKey> {
        public void Configure(EntityTypeBuilder<RefreshToken<TKey>> builder) {
            builder.ToTable("AuthenticationRefreshTokens");
            builder.HasKey(token => token.Id);
            builder.Property(token => token.TokenHash).HasMaxLength(64).IsRequired();
            builder.Property(token => token.SessionName).HasMaxLength(100);
            builder.HasIndex(token => token.TokenHash).IsUnique();
            builder.HasIndex(token => new { token.UserId, token.FamilyId });
            builder.HasIndex(token => new { token.FamilyId, token.RevokedAt });
            builder.HasIndex(token => token.ExpiresAt);
        }
    }
}