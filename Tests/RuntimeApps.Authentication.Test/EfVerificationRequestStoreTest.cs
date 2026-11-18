using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.EF.Extensions;
using RuntimeApps.Authentication.EF.Store;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Test {
    public class EfVerificationRequestStoreTest {
        [Fact]
        public async Task RequestCanBeCreatedResentAndConsumedOnlyOnce() {
            await using var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var options = new DbContextOptionsBuilder<TestDbContext>().UseSqlite(connection).Options;
            await using var db = new TestDbContext(options);
            await db.Database.EnsureCreatedAsync();
            var store = new EfVerificationRequestStore<TestDbContext, int>(db);
            var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
            var request = CreateRequest(10, "handle-hash", now);

            Assert.True(await store.TryCreateAsync(request, now.AddHours(-1), 5));
            Assert.True(request.Id > 0);
            Assert.True(await store.TrySetInitialVerifierAsync(request.Id, "protected-v1", now, now.AddMinutes(10)));

            var persisted = await store.FindByHandleHashAsync("handle-hash");
            Assert.NotNull(persisted);
            Assert.Equal(1, persisted.CodeVersion);

            Assert.True(await store.TryIncrementFailedAttemptsAsync(request.Id, 1, 5, now.AddSeconds(10)));

            var resentAt = now.AddMinutes(2);
            Assert.True(await store.TryResendAsync(
                request.Id, 1, "protected-v2", resentAt, resentAt.AddMinutes(10),
                TimeSpan.FromSeconds(60), now.AddHours(-1), 5));
            Assert.False(await store.TryConsumeAsync(request.Id, 1, resentAt.AddSeconds(1)));
            Assert.True(await store.TryConsumeAsync(request.Id, 2, resentAt.AddSeconds(1)));
            Assert.False(await store.TryConsumeAsync(request.Id, 2, resentAt.AddSeconds(2)));

            var completed = await db.Set<VerificationRequest<int>>().AsNoTracking().SingleAsync();
            Assert.Equal(VerificationRequestStatus.Completed, completed.Status);
            Assert.Equal(2, completed.CodeVersion);
            Assert.Equal(1, completed.FailedAttempts);
        }

        [Fact]
        public async Task SendRateLimitIsSharedAcrossRequestsForSameDestination() {
            await using var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var options = new DbContextOptionsBuilder<TestDbContext>().UseSqlite(connection).Options;
            await using var db = new TestDbContext(options);
            await db.Database.EnsureCreatedAsync();
            var store = new EfVerificationRequestStore<TestDbContext, int>(db);
            var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

            Assert.True(await store.TryCreateAsync(CreateRequest(10, "first", now), now.AddHours(-1), 1));
            Assert.False(await store.TryCreateAsync(CreateRequest(20, "second", now.AddSeconds(1)), now.AddHours(-1), 1));
        }

        private static VerificationRequest<int> CreateRequest(int userId, string handleHash, DateTimeOffset now) => new() {
            UserId = userId,
            Purpose = VerificationPurpose.Registration,
            Channel = VerificationChannel.Email,
            Destination = "person@example.com",
            NormalizedDestination = "PERSON@EXAMPLE.COM",
            PublicHandleHash = handleHash,
            CodeVerifier = string.Empty,
            CodeVersion = 0,
            FailedAttempts = 0,
            SendCount = 1,
            CreatedAt = now,
            LastSentAt = now,
            ExpiresAt = now.AddMinutes(10),
            Status = VerificationRequestStatus.Pending
        };

        private sealed class TestDbContext : IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int> {
            public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }

            protected override void OnModelCreating(ModelBuilder modelBuilder) {
                base.OnModelCreating(modelBuilder);
                modelBuilder.AddVerificationRequestEntity<int>();
            }
        }
    }
}