using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using RuntimeApps.Authentication.EF.Configurations;
using RuntimeApps.Authentication.EF.Features.RefreshTokens.Configurations;
using RuntimeApps.Authentication.EF.Features.Verification.Configurations;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Features.Verification.Models;
using Microsoft.AspNetCore.Identity;
namespace RuntimeApps.Authentication.Test {
    public class EfModelConfigurationTest {
        [Fact]
        public void ConsolidatedExtension_AddsSelectedFeaturesOnly() {
            using var refreshOnly = new RefreshOnlyDbContext();
            Assert.NotNull(refreshOnly.Model.FindEntityType(typeof(RefreshToken<int>)));
            Assert.Null(refreshOnly.Model.FindEntityType(typeof(VerificationRequest<int>)));
            Assert.Null(refreshOnly.Model.FindEntityType(typeof(VerificationSend)));

            using var all = new ConsolidatedDbContext();
            Assert.NotNull(all.Model.FindEntityType(typeof(RefreshToken<int>)));
            Assert.NotNull(all.Model.FindEntityType(typeof(VerificationRequest<int>)));
            Assert.NotNull(all.Model.FindEntityType(typeof(VerificationSend)));
        }

        [Fact]
        public void ConsolidatedExtension_ProducesSameModelAsGranularMethods() {
            using var consolidated = new ConsolidatedDbContext();
            using var granular = new GranularDbContext();

            foreach(var type in new[] { typeof(RefreshToken<int>), typeof(VerificationRequest<int>), typeof(VerificationSend) }) {
                var left = consolidated.Model.FindEntityType(type);
                var right = granular.Model.FindEntityType(type);
                Assert.Equal(right.GetTableName(), left.GetTableName());
                Assert.Equal(
                    right.GetProperties().Select(p => p.Name).OrderBy(n => n),
                    left.GetProperties().Select(p => p.Name).OrderBy(n => n));
                Assert.Equal(
                    right.GetIndexes().Select(i => string.Join(",", i.Properties.Select(p => p.Name)) + i.IsUnique).OrderBy(n => n),
                    left.GetIndexes().Select(i => string.Join(",", i.Properties.Select(p => p.Name)) + i.IsUnique).OrderBy(n => n));
            }
        }

        [Fact]
        public void ConsolidatedExtension_WithoutSelectedFeatures_Throws() {
            var exception = Assert.Throws<InvalidOperationException>(() => {
                using var context = new EmptySelectionDbContext();
                _ = context.Model;
            });
            Assert.Contains("Select at least one feature", exception.ToString());
        }

        [Fact]
        public void RefreshTokenModel_DefinesExpectedConstraintsAndMappings() {
            using var context = new GranularDbContext();
            var entity = context.Model.FindEntityType(typeof(RefreshToken<int>));

            Assert.Equal("AuthenticationRefreshTokens", entity.GetTableName());
            var hashIndex = entity.GetIndexes().Single(i => i.Properties.Select(p => p.Name).SequenceEqual(new[] { "TokenHash" }));
            Assert.True(hashIndex.IsUnique);
            Assert.Equal(64, entity.FindProperty(nameof(RefreshToken<int>.TokenHash)).GetMaxLength());
            Assert.False(entity.FindProperty(nameof(RefreshToken<int>.TokenHash)).IsNullable);
            Assert.Equal(100, entity.FindProperty(nameof(RefreshToken<int>.SessionName)).GetMaxLength());
            Assert.True(entity.FindProperty(nameof(RefreshToken<int>.SessionName)).IsNullable);
            Assert.True(entity.FindProperty(nameof(RefreshToken<int>.RevokedAt)).IsNullable);
            Assert.IsType<DateTimeOffsetToBinaryConverter>(entity.FindProperty(nameof(RefreshToken<int>.ExpiresAt)).GetValueConverter());
            Assert.Contains(entity.GetIndexes(), i => i.Properties.Select(p => p.Name).SequenceEqual(new[] { "FamilyId", "RevokedAt" }));
            Assert.Contains(entity.GetIndexes(), i => i.Properties.Select(p => p.Name).SequenceEqual(new[] { "UserId", "RevokedAt" }));
            Assert.Empty(entity.GetForeignKeys());
        }

        [Fact]
        public void RefreshTokenModel_StringKeysHaveBoundedLength() {
            using var context = new StringKeyDbContext();
            var entity = context.Model.FindEntityType(typeof(RefreshToken<string>));
            Assert.Equal(450, entity.FindProperty(nameof(RefreshToken<string>.UserId)).GetMaxLength());
            Assert.True(entity.FindProperty(nameof(RefreshToken<string>.ReplacedByTokenId)).IsNullable);
        }

        [Fact]
        public void VerificationModel_DefinesExpectedConstraintsAndMappings() {
            using var context = new GranularDbContext();
            var request = context.Model.FindEntityType(typeof(VerificationRequest<int>));
            var send = context.Model.FindEntityType(typeof(VerificationSend));

            Assert.Equal("AuthenticationVerificationRequests", request.GetTableName());
            Assert.Equal("AuthenticationVerificationSends", send.GetTableName());
            Assert.True(request.GetIndexes().Single(i => i.Properties.Select(p => p.Name).SequenceEqual(new[] { "PublicHandleHash" })).IsUnique);
            Assert.Equal(64, request.FindProperty(nameof(VerificationRequest<int>.PublicHandleHash)).GetMaxLength());
            Assert.Equal(512, request.FindProperty(nameof(VerificationRequest<int>.NormalizedDestination)).GetMaxLength());
            Assert.Equal(32, request.FindProperty(nameof(VerificationRequest<int>.Status)).GetMaxLength());
            Assert.Equal(typeof(string), request.FindProperty(nameof(VerificationRequest<int>.Status)).GetValueConverter().ProviderClrType);
            Assert.True(request.FindProperty(nameof(VerificationRequest<int>.CustomPurpose)).IsNullable);
            Assert.True(send.FindProperty(nameof(VerificationSend.CustomPurpose)).IsNullable);
            Assert.Equal(128, send.FindProperty(nameof(VerificationSend.CustomChannel)).GetMaxLength());
            Assert.Contains(send.GetIndexes(), i => i.Properties.Select(p => p.Name).SequenceEqual(
                new[] { "NormalizedDestination", "Purpose", "Channel", "SentAt" }));
            Assert.Empty(request.GetForeignKeys());
        }

        [Fact]
        public void GranularMethods_StillWorkTogetherWithIdentityModel() {
            using var context = new GranularDbContext();
            Assert.NotNull(context.Model.FindEntityType(typeof(IdentityUser<int>)));
            Assert.NotNull(context.Model.FindEntityType(typeof(RefreshToken<int>)));
        }

        private static DbContextOptions<T> Options<T>() where T : DbContext =>
            new DbContextOptionsBuilder<T>().UseSqlite("Data Source=:memory:").Options;

        private sealed class RefreshOnlyDbContext(): IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int>(Options<RefreshOnlyDbContext>()) {
            protected override void OnModelCreating(ModelBuilder modelBuilder) {
                base.OnModelCreating(modelBuilder);
                modelBuilder.AddRuntimeAppsAuthenticationEntities<int>(options => options.UseRefreshTokens());
            }
        }

        private sealed class ConsolidatedDbContext(): IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int>(Options<ConsolidatedDbContext>()) {
            protected override void OnModelCreating(ModelBuilder modelBuilder) {
                base.OnModelCreating(modelBuilder);
                modelBuilder.AddRuntimeAppsAuthenticationEntities<int>(options => options.UseRefreshTokens().UseVerificationRequests());
            }
        }

        private sealed class GranularDbContext(): IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int>(Options<GranularDbContext>()) {
            protected override void OnModelCreating(ModelBuilder modelBuilder) {
                base.OnModelCreating(modelBuilder);
                modelBuilder.AddRefreshTokenEntity<int>();
                modelBuilder.AddVerificationRequestEntity<int>();
            }
        }

        private sealed class EmptySelectionDbContext(): DbContext(Options<EmptySelectionDbContext>()) {
            protected override void OnModelCreating(ModelBuilder modelBuilder) =>
                modelBuilder.AddRuntimeAppsAuthenticationEntities<int>(_ => { });
        }

        private sealed class StringKeyDbContext(): IdentityDbContext<IdentityUser, IdentityRole, string>(Options<StringKeyDbContext>()) {
            protected override void OnModelCreating(ModelBuilder modelBuilder) {
                base.OnModelCreating(modelBuilder);
                modelBuilder.AddRuntimeAppsAuthenticationEntities<string>(options => options.UseRefreshTokens());
            }
        }
    }
}
