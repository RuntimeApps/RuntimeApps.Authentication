using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
namespace RuntimeApps.Authentication.EF.Features.RefreshTokens.Configurations {
    public sealed class RefreshTokenConfiguration<TKey>: IEntityTypeConfiguration<RefreshToken<TKey>>
        where TKey : IEquatable<TKey> {
        public void Configure(EntityTypeBuilder<RefreshToken<TKey>> builder) {
            builder.ToTable("AuthenticationRefreshTokens");
            builder.HasKey(token => token.Id);
            builder.Property(token => token.Id).ValueGeneratedOnAdd();
            // Generic reference-type keys (for example string) use null until the first rotation;
            // value-type keys use their default value and HasReplacement distinguishes that state.
            builder.Property(token => token.ReplacedByTokenId).IsRequired(typeof(TKey).IsValueType);
            builder.Property(token => token.HasReplacement).IsRequired();
            builder.Property(token => token.UserId).IsRequired();
            if(typeof(TKey) == typeof(string))
                builder.Property(token => token.UserId).HasMaxLength(450);
            builder.Property(token => token.FamilyId).IsRequired();
            // Store UTC DateTimeOffset values as binary ticks so expiry predicates are
            // supported consistently by relational providers such as SQLite.
            builder.Property(token => token.CreatedAt).HasConversion(new DateTimeOffsetToBinaryConverter());
            builder.Property(token => token.ExpiresAt).HasConversion(new DateTimeOffsetToBinaryConverter());
            builder.Property(token => token.AbsoluteExpiresAt).IsRequired().HasConversion(new DateTimeOffsetToBinaryConverter());
            builder.Property(token => token.RevokedAt).HasConversion(new DateTimeOffsetToBinaryConverter());
            builder.Property(token => token.TokenHash).HasMaxLength(64).IsRequired();
            builder.Property(token => token.SessionName).HasMaxLength(100);
            builder.HasIndex(token => token.TokenHash).IsUnique();
            builder.HasIndex(token => new { token.UserId, token.FamilyId });
            builder.HasIndex(token => new { token.UserId, token.RevokedAt });
            builder.HasIndex(token => new { token.FamilyId, token.RevokedAt });
            builder.HasIndex(token => token.ExpiresAt);
            // Serves the revoked/rotated branch of cleanup; (UserId, RevokedAt) and (FamilyId, RevokedAt) do not
            // support a range scan on RevokedAt alone.
            builder.HasIndex(token => token.RevokedAt);
        }
    }
}
