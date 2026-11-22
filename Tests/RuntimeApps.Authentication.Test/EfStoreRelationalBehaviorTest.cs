using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.EF.Configurations;
using RuntimeApps.Authentication.EF.Features.RefreshTokens.Stores;
using RuntimeApps.Authentication.EF.Features.Verification.Stores;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Features.Verification.Models;
namespace RuntimeApps.Authentication.Test {
    /// <summary>Relational (SQLite) tests for transactions and conditional updates. EF InMemory is not used.</summary>
    public class EfStoreRelationalBehaviorTest {
        private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        [Fact]
        public async Task TryRotateAsync_ConcurrentAttemptsOnSameToken_OnlyOneSucceeds() {
            var cancellationToken = TestContext.Current.CancellationToken;
            var path = Path.Combine(Path.GetTempPath(), $"runtimeapps-{Guid.NewGuid():N}.db");
            try {
                await using(var setup = CreateFileContext(path)) {
                    await setup.Database.EnsureCreatedAsync(cancellationToken);
                    await new EfRefreshTokenStore<TestDbContext, int>(setup)
                        .CreateAsync(NewToken(10, Guid.NewGuid(), "A"), cancellationToken);
                }

                Task<bool> Rotate(string replacementPrefix) => Task.Run(async () => {
                    await using var db = CreateFileContext(path);
                    var store = new EfRefreshTokenStore<TestDbContext, int>(db);
                    var current = await store.FindByHashAsync("A".PadRight(64, '0'), cancellationToken);
                    return await store.TryRotateAsync(
                        current.Id, current.TokenHash, NewToken(10, current.FamilyId, replacementPrefix), Now, cancellationToken);
                }, cancellationToken);

                var results = await Task.WhenAll(Rotate("B"), Rotate("C"));

                Assert.Single(results, succeeded => succeeded);
                await using var verify = CreateFileContext(path);
                var rows = await verify.Set<RefreshToken<int>>().AsNoTracking().ToListAsync(cancellationToken);
                Assert.Equal(2, rows.Count);
                Assert.Single(rows, token => token.RevokedAt != null);
            } finally {
                SqliteConnection.ClearAllPools();
                if(File.Exists(path))
                    File.Delete(path);
            }
        }

        [Fact]
        public async Task TryRotateAsync_ExpiredToken_RollsBackReplacementAndDetachesIt() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var db = CreateContext(connection);
            await db.Database.EnsureCreatedAsync(cancellationToken);
            var store = new EfRefreshTokenStore<TestDbContext, int>(db);
            var original = NewToken(10, Guid.NewGuid(), "A");
            await store.CreateAsync(original, cancellationToken);
            var replacement = NewToken(10, original.FamilyId, "B");

            var rotated = await store.TryRotateAsync(original.Id, original.TokenHash, replacement, Now.AddDays(31), cancellationToken);

            Assert.False(rotated);
            Assert.Equal(EntityState.Detached, db.Entry(replacement).State);
            Assert.Equal(0, replacement.Id);
            Assert.Equal(1, await db.Set<RefreshToken<int>>().AsNoTracking().CountAsync(cancellationToken));
            Assert.Null(await store.FindByHashAsync(replacement.TokenHash, cancellationToken));
        }

        [Fact]
        public async Task TryRotateAsync_ConsumedToken_CannotBeRotatedAgain() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var db = CreateContext(connection);
            await db.Database.EnsureCreatedAsync(cancellationToken);
            var store = new EfRefreshTokenStore<TestDbContext, int>(db);
            var original = NewToken(10, Guid.NewGuid(), "A");
            await store.CreateAsync(original, cancellationToken);

            Assert.True(await store.TryRotateAsync(original.Id, original.TokenHash, NewToken(10, original.FamilyId, "B"), Now, cancellationToken));
            Assert.False(await store.TryRotateAsync(original.Id, original.TokenHash, NewToken(10, original.FamilyId, "C"), Now, cancellationToken));

            Assert.Equal(2, await db.Set<RefreshToken<int>>().AsNoTracking().CountAsync(cancellationToken));
        }

        [Fact]
        public async Task TryRotateAsync_WrongExpectedHash_IsRejected() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var db = CreateContext(connection);
            await db.Database.EnsureCreatedAsync(cancellationToken);
            var store = new EfRefreshTokenStore<TestDbContext, int>(db);
            var original = NewToken(10, Guid.NewGuid(), "A");
            await store.CreateAsync(original, cancellationToken);

            Assert.False(await store.TryRotateAsync(
                original.Id, "Z".PadRight(64, '0'), NewToken(10, original.FamilyId, "B"), Now, cancellationToken));
            Assert.Null((await store.FindByHashAsync(original.TokenHash, cancellationToken)).RevokedAt);
        }

        [Fact]
        public async Task TryIncrementFailedAttemptsAsync_LocksRequestAtMaximumAttempts() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var db = CreateContext(connection);
            await db.Database.EnsureCreatedAsync(cancellationToken);
            var store = new EfVerificationRequestStore<TestDbContext, int>(db);
            var request = NewRequest(10, "handle", Now);
            Assert.True(await store.TryCreateAsync(request, Now.AddHours(-1), 5, cancellationToken));
            Assert.True(await store.TrySetInitialVerifierAsync(request.Id, "v1", Now, Now.AddMinutes(10), cancellationToken));

            Assert.True(await store.TryIncrementFailedAttemptsAsync(request.Id, 1, 2, Now, cancellationToken));
            Assert.Equal(VerificationRequestStatus.Pending, (await store.FindByHandleHashAsync("handle", cancellationToken)).Status);

            Assert.True(await store.TryIncrementFailedAttemptsAsync(request.Id, 1, 2, Now, cancellationToken));
            var locked = await store.FindByHandleHashAsync("handle", cancellationToken);
            Assert.Equal(VerificationRequestStatus.Locked, locked.Status);
            Assert.Equal(2, locked.FailedAttempts);

            Assert.False(await store.TryIncrementFailedAttemptsAsync(request.Id, 1, 2, Now, cancellationToken));
            Assert.False(await store.TryConsumeAsync(request.Id, 1, Now, cancellationToken));
        }

        [Fact]
        public async Task TryResendAsync_WithinCooldown_IsRejectedAndNotCounted() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var db = CreateContext(connection);
            await db.Database.EnsureCreatedAsync(cancellationToken);
            var store = new EfVerificationRequestStore<TestDbContext, int>(db);
            var request = NewRequest(10, "handle", Now);
            Assert.True(await store.TryCreateAsync(request, Now.AddHours(-1), 5, cancellationToken));
            Assert.True(await store.TrySetInitialVerifierAsync(request.Id, "v1", Now, Now.AddMinutes(10), cancellationToken));

            var tooSoon = Now.AddSeconds(5);
            Assert.False(await store.TryResendAsync(
                request.Id, 1, "v2", tooSoon, tooSoon.AddMinutes(10), TimeSpan.FromSeconds(60), Now.AddHours(-1), 5, cancellationToken));

            var persisted = await store.FindByHandleHashAsync("handle", cancellationToken);
            Assert.Equal(1, persisted.CodeVersion);
            Assert.Equal(1, await db.Set<VerificationSend>().CountAsync(cancellationToken));
        }

        [Fact]
        public async Task CustomPurposes_HaveSeparateSendLimitsAndDoNotSupersedeEachOther() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var db = CreateContext(connection);
            await db.Database.EnsureCreatedAsync(cancellationToken);
            var store = new EfVerificationRequestStore<TestDbContext, int>(db);

            var first = NewRequest(10, "first", Now, customPurpose: "alpha");
            var second = NewRequest(10, "second", Now, customPurpose: "beta");
            var third = NewRequest(10, "third", Now.AddSeconds(1), customPurpose: "alpha");

            Assert.True(await store.TryCreateAsync(first, Now.AddHours(-1), 1, cancellationToken));
            Assert.True(await store.TryCreateAsync(second, Now.AddHours(-1), 1, cancellationToken));
            Assert.Equal(VerificationRequestStatus.Pending, (await store.FindByHandleHashAsync("first", cancellationToken)).Status);

            Assert.False(await store.TryCreateAsync(third, Now.AddHours(-1), 1, cancellationToken));
            Assert.Equal(EntityState.Detached, db.Entry(third).State);
        }

        [Fact]
        public async Task TryCreateAsync_SupersedesPreviousPendingRequestWithSameCustomPurpose() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var db = CreateContext(connection);
            await db.Database.EnsureCreatedAsync(cancellationToken);
            var store = new EfVerificationRequestStore<TestDbContext, int>(db);

            Assert.True(await store.TryCreateAsync(NewRequest(10, "first", Now, customPurpose: "alpha"), Now.AddHours(-1), 5, cancellationToken));
            Assert.True(await store.TryCreateAsync(NewRequest(10, "second", Now.AddSeconds(1), customPurpose: "alpha"), Now.AddHours(-1), 5, cancellationToken));

            Assert.Equal(VerificationRequestStatus.Superseded, (await store.FindByHandleHashAsync("first", cancellationToken)).Status);
            Assert.Equal(VerificationRequestStatus.Pending, (await store.FindByHandleHashAsync("second", cancellationToken)).Status);
        }

        private static RefreshToken<int> NewToken(int userId, Guid familyId, string hashPrefix) => new() {
            UserId = userId,
            FamilyId = familyId,
            TokenHash = hashPrefix.PadRight(64, '0'),
            CreatedAt = Now,
            ExpiresAt = Now.AddDays(30)
        };

        private static VerificationRequest<int> NewRequest(int userId, string handleHash, DateTimeOffset now, string customPurpose = null) => new() {
            UserId = userId,
            Purpose = customPurpose == null ? VerificationPurpose.Registration : VerificationPurpose.Custom,
            Channel = VerificationChannel.Email,
            CustomPurpose = customPurpose,
            Destination = "person@example.com",
            NormalizedDestination = "PERSON@EXAMPLE.COM",
            PublicHandleHash = handleHash,
            CodeVerifier = string.Empty,
            SendCount = 1,
            CreatedAt = now,
            LastSentAt = now,
            ExpiresAt = now.AddMinutes(10),
            Status = VerificationRequestStatus.Pending
        };

        private static async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken) {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(cancellationToken);
            return connection;
        }

        private static TestDbContext CreateContext(SqliteConnection connection) =>
            new(new DbContextOptionsBuilder<TestDbContext>().UseSqlite(connection).Options);

        private static TestDbContext CreateFileContext(string path) =>
            new(new DbContextOptionsBuilder<TestDbContext>().UseSqlite($"Data Source={path};Pooling=False").Options);

        private sealed class TestDbContext(DbContextOptions<TestDbContext> options)
            : IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int>(options) {
            protected override void OnModelCreating(ModelBuilder modelBuilder) {
                base.OnModelCreating(modelBuilder);
                modelBuilder.AddRuntimeAppsAuthenticationEntities<int>(features => features.UseRefreshTokens().UseVerificationRequests());
            }
        }
    }
}
