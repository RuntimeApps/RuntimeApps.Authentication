using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using RuntimeApps.Authentication.Features.Verification.Models;
namespace RuntimeApps.Authentication.EF.Features.Verification.Configurations {
    public sealed class VerificationRequestConfiguration<TKey> : IEntityTypeConfiguration<VerificationRequest<TKey>>
        where TKey : IEquatable<TKey> {
        public void Configure(EntityTypeBuilder<VerificationRequest<TKey>> builder) {
            builder.ToTable("AuthenticationVerificationRequests");
            builder.HasKey(request => request.Id);
            builder.Property(request => request.Id).ValueGeneratedOnAdd();
            builder.Property(request => request.UserId).IsRequired();
            builder.Property(request => request.Purpose).HasConversion<string>().HasMaxLength(32).IsRequired();
            builder.Property(request => request.Channel).HasConversion<string>().HasMaxLength(32).IsRequired();
            builder.Property(request => request.Status).HasConversion<string>().HasMaxLength(32).IsRequired();
            builder.Property(request => request.CustomPurpose).HasMaxLength(128);
            builder.Property(request => request.CustomChannel).HasMaxLength(128);
            builder.Property(request => request.Destination).HasMaxLength(512).IsRequired();
            builder.Property(request => request.NormalizedDestination).HasMaxLength(512).IsRequired();
            builder.Property(request => request.PublicHandleHash).HasMaxLength(64).IsRequired();
            builder.Property(request => request.CodeVerifier).IsRequired();
            builder.Property(request => request.CreatedAt).HasConversion(new DateTimeOffsetToBinaryConverter());
            builder.Property(request => request.LastSentAt).HasConversion(new DateTimeOffsetToBinaryConverter());
            builder.Property(request => request.ExpiresAt).HasConversion(new DateTimeOffsetToBinaryConverter());
            builder.Property(request => request.CompletedAt).HasConversion(new DateTimeOffsetToBinaryConverter());
            builder.HasIndex(request => request.PublicHandleHash).IsUnique();
            builder.HasIndex(request => new {
                request.NormalizedDestination,
                request.Purpose,
                request.Channel,
                request.CreatedAt
            });
            builder.HasIndex(request => new { request.UserId, request.Purpose, request.Status });
            builder.HasIndex(request => new { request.Status, request.ExpiresAt });
        }
    }
}
