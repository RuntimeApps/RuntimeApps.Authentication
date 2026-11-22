using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using RuntimeApps.Authentication.EF.Configurations;
using RuntimeApps.Authentication.EF.Features.RefreshTokens.Stores;
using RuntimeApps.Authentication.EF.Features.Verification.Stores;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Features.Verification.Models;
namespace RuntimeApps.Authentication.Test {
    /// <summary>
    /// Regression tests for providers configured with a retrying execution strategy (for example
    /// EnableRetryOnFailure), which reject transactions started outside the strategy.
    /// </summary>
    public class EfExecutionStrategyTest {
        private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        [Fact]
        public async Task EfRefreshTokenStore_RotatesTokensWithRetryingExecutionStrategy() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(cancellationToken);
            await using var db = CreateContext(connection);
            await db.Database.EnsureCreatedAsync(cancellationToken);
            var store = new EfRefreshTokenStore<RetryingDbContext, int>(db);
            var original = new RefreshToken<int> {
                UserId = 10, FamilyId = Guid.NewGuid(), TokenHash = "A".PadRight(64, '0'),
                CreatedAt = Now, ExpiresAt = Now.AddDays(30)
            };
            await store.CreateAsync(original, cancellationToken);
            var replacement = new RefreshToken<int> {
                UserId = 10, FamilyId = original.FamilyId, TokenHash = "B".PadRight(64, '0'),
                CreatedAt = Now, ExpiresAt = Now.AddDays(30)
            };

            Assert.True(await store.TryRotateAsync(original.Id, original.TokenHash, replacement, Now, cancellationToken));
            Assert.NotNull(await store.FindByHashAsync(replacement.TokenHash, cancellationToken));
        }

        [Fact]
        public async Task EfVerificationRequestStore_CreatesAndResendsWithRetryingExecutionStrategy() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(cancellationToken);
            await using var db = CreateContext(connection);
            await db.Database.EnsureCreatedAsync(cancellationToken);
            var store = new EfVerificationRequestStore<RetryingDbContext, int>(db);
            var request = new VerificationRequest<int> {
                UserId = 10, Purpose = VerificationPurpose.Registration, Channel = VerificationChannel.Email,
                Destination = "person@example.com", NormalizedDestination = "PERSON@EXAMPLE.COM",
                PublicHandleHash = "handle", CodeVerifier = string.Empty, SendCount = 1,
                CreatedAt = Now, LastSentAt = Now, ExpiresAt = Now.AddMinutes(10),
                Status = VerificationRequestStatus.Pending
            };

            Assert.True(await store.TryCreateAsync(request, Now.AddHours(-1), 5, cancellationToken));
            Assert.True(await store.TrySetInitialVerifierAsync(request.Id, "v1", Now, Now.AddMinutes(10), cancellationToken));
            var resentAt = Now.AddMinutes(2);
            Assert.True(await store.TryResendAsync(
                request.Id, 1, "v2", resentAt, resentAt.AddMinutes(10), TimeSpan.FromSeconds(60), Now.AddHours(-1), 5, cancellationToken));
        }

        private static RetryingDbContext CreateContext(SqliteConnection connection) =>
            new(new DbContextOptionsBuilder<RetryingDbContext>()
                .UseSqlite(connection)
                .ReplaceService<IExecutionStrategyFactory, RetryingExecutionStrategyFactory>()
                .Options);

        private sealed class RetryingExecutionStrategy(ExecutionStrategyDependencies dependencies)
            : ExecutionStrategy(dependencies, 3, TimeSpan.FromMilliseconds(10)) {
            protected override bool ShouldRetryOn(Exception exception) => false;
        }

        private sealed class RetryingExecutionStrategyFactory(ExecutionStrategyDependencies dependencies)
            : RelationalExecutionStrategyFactory(dependencies) {
            protected override IExecutionStrategy CreateDefaultStrategy(ExecutionStrategyDependencies dependencies) =>
                new RetryingExecutionStrategy(dependencies);
        }

        private sealed class RetryingDbContext(DbContextOptions<RetryingDbContext> options)
            : IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int>(options) {
            protected override void OnModelCreating(ModelBuilder modelBuilder) {
                base.OnModelCreating(modelBuilder);
                modelBuilder.AddRuntimeAppsAuthenticationEntities<int>(features => features.UseRefreshTokens().UseVerificationRequests());
            }
        }
    }
}
