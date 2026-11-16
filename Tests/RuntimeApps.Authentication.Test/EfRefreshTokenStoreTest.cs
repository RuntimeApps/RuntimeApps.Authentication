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
                Id = default,
                UserId = 10,
                FamilyId = default,
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

        [Fact]
        public async Task RevokeAllAsync_RevokesOnlyTheSpecifiedUsersSessions() {
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
            var firstUserFamily = Guid.NewGuid();
            var secondUserFamily = Guid.NewGuid();
            var otherUserFamily = Guid.NewGuid();

            foreach(var token in new[] {
                CreateToken(10, firstUserFamily, "A", now),
                CreateToken(10, secondUserFamily, "B", now),
                CreateToken(20, otherUserFamily, "C", now)
            }) {
                await store.CreateAsync(token, cancellationToken);
            }

            await store.RevokeFamilyAsync(firstUserFamily, now.AddMinutes(1), cancellationToken);
            var revokedCount = await store.RevokeAllAsync(10, now.AddMinutes(2), cancellationToken);

            var records = await dbContext.Set<RefreshToken<int>>()
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            Assert.Equal(1, revokedCount);
            Assert.Equal(now.AddMinutes(1), records.Single(token => token.FamilyId == firstUserFamily).RevokedAt);
            Assert.Equal(now.AddMinutes(2), records.Single(token => token.FamilyId == secondUserFamily).RevokedAt);
            Assert.Null(records.Single(token => token.UserId == 20).RevokedAt);
        }

        private static RefreshToken<int> CreateToken(int userId, Guid familyId, string hashPrefix, DateTimeOffset now) => new() {
            Id = default,
            UserId = userId,
            FamilyId = familyId,
            TokenHash = hashPrefix.PadRight(64, '0'),
            CreatedAt = now,
            ExpiresAt = now.AddDays(30)
        };

        private sealed class TestDbContext : IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int> {
            public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }

            protected override void OnModelCreating(ModelBuilder modelBuilder) {
                base.OnModelCreating(modelBuilder);
                modelBuilder.AddRefreshTokenEntity<int>();
            }
        }
    }
}