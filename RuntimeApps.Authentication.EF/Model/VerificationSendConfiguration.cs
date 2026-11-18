using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.EF.Model {
    public sealed class VerificationSendConfiguration : IEntityTypeConfiguration<VerificationSend> {
        public void Configure(EntityTypeBuilder<VerificationSend> builder) {
            builder.ToTable("AuthenticationVerificationSends");
            builder.HasKey(send => send.Id);
            builder.Property(send => send.Id).ValueGeneratedOnAdd();
            builder.Property(send => send.NormalizedDestination).HasMaxLength(512).IsRequired();
            builder.Property(send => send.Purpose).HasConversion<string>().HasMaxLength(32).IsRequired();
            builder.Property(send => send.Channel).HasConversion<string>().HasMaxLength(32).IsRequired();
            builder.Property(send => send.SentAt).HasConversion(new DateTimeOffsetToBinaryConverter());
            builder.HasIndex(send => send.SentAt);
            builder.HasIndex(send => new {
                send.NormalizedDestination,
                send.Purpose,
                send.Channel,
                send.SentAt
            });
        }
    }
}