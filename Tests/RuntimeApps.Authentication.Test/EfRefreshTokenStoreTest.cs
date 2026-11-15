using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.EF.Extensions;
using RuntimeApps.Authentication.EF.Store;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Test {
    public class EfRefreshTokenStoreTest {
        [Fact]
        public async Task TryRotateAsync_ConsumesOldTokenAndPersistsReplacementAtomically() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(cancellationToken);

            var options = new DbContextOptionsBuilder<TestDbContext>()
                .UseSqlite(connection)
                .Options;
            await using var dbContext = new TestDbContext(options);
            await dbContext.Database.EnsureCreatedAsync(cancellationToken);

            var store = new EfRefreshTokenStore<TestDbContext, int>(dbContext);
            var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
            var original = new RefreshToken<int> {
                Id = Guid.NewGuid(),
                UserId = 10,
                FamilyId = Guid.NewGuid(),
                TokenHash = new string('A', 64),
                CreatedAt = now,
                ExpiresAt = now.AddDays(30)
            };
            var replacement = new RefreshToken<int> {
                Id = Guid.NewGuid(),
                UserId = original.UserId,
                FamilyId = original.FamilyId,
                TokenHash = new string('B', 64),
                CreatedAt = now,
                ExpiresAt = now.AddDays(30)
            };

            await store.CreateAsync(original, cancellationToken);
            var rotated = await store.TryRotateAsync(original.Id, original.TokenHash, replacement, now, cancellationToken);

            Assert.True(rotated);
            var consumed = await store.FindByHashAsync(original.TokenHash, cancellationToken);
            var active = await store.FindByHashAsync(replacement.TokenHash, cancellationToken);
            Assert.NotNull(consumed);
            Assert.Equal(replacement.Id, consumed.ReplacedByTokenId);
            Assert.Equal(now, consumed.RevokedAt);
            Assert.NotNull(active);
            Assert.Null(active.RevokedAt);
            Assert.Equal(original.FamilyId, active.FamilyId);
        }

        private sealed class TestDbContext : IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int> {
            public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }

            protected override void OnModelCreating(ModelBuilder modelBuilder) {
                base.OnModelCreating(modelBuilder);
                modelBuilder.AddRefreshTokenEntity<int>();
            }
        }
    }
}