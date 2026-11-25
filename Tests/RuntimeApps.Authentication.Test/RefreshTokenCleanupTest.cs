using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.EF.Features.RefreshTokens.Configurations;
using RuntimeApps.Authentication.EF.Features.RefreshTokens.Stores;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Features.RefreshTokens.Services;
namespace RuntimeApps.Authentication.Test {
    public class RefreshTokenCleanupTest {
        private static readonly DateTimeOffset Now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
        private static readonly TimeSpan Retention = TimeSpan.FromDays(30);

        // ---- EF store ---------------------------------------------------------------------------------

        [Fact]
        public async Task DeleteInactiveAsync_DeletesOnlyRecordsOlderThanRetention() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var fixture = await StoreFixture.CreateAsync(cancellationToken);
            var cutoff = Now - Retention;

            await fixture.SeedAsync("ACTIVE", expiresAt: Now.AddDays(10), cancellationToken: cancellationToken);
            await fixture.SeedAsync("REVOKEDRECENT", expiresAt: Now.AddDays(10), revokedAt: Now.AddDays(-5), cancellationToken: cancellationToken);
            await fixture.SeedAsync("REVOKEDOLD", expiresAt: Now.AddDays(10), revokedAt: Now.AddDays(-31), cancellationToken: cancellationToken);
            await fixture.SeedAsync("REVOKEDATCUTOFF", expiresAt: Now.AddDays(10), revokedAt: cutoff, cancellationToken: cancellationToken);
            await fixture.SeedAsync("EXPIREDRECENT", expiresAt: Now.AddDays(-5), cancellationToken: cancellationToken);
            await fixture.SeedAsync("EXPIREDOLD", expiresAt: Now.AddDays(-31), cancellationToken: cancellationToken);
            // Expired long ago but revoked recently: the revocation time decides, so it is still retained.
            await fixture.SeedAsync("EXPIREDREVOKEDRECENT", expiresAt: Now.AddDays(-60), revokedAt: Now.AddDays(-5), cancellationToken: cancellationToken);

            var deleted = await fixture.Store.DeleteInactiveAsync(Now, Retention, 100, cancellationToken);

            Assert.Equal(2, deleted);
            var remaining = await fixture.RemainingHashPrefixesAsync(cancellationToken);
            Assert.Equal(
                new[] { "ACTIVE", "EXPIREDRECENT", "EXPIREDREVOKEDRECENT", "REVOKEDATCUTOFF", "REVOKEDRECENT" },
                remaining.OrderBy(name => name, StringComparer.Ordinal).ToArray());
        }

        [Fact]
        public async Task DeleteInactiveAsync_RemovesOldRotatedTokenButKeepsTheLiveTokenOfTheSameSession() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var fixture = await StoreFixture.CreateAsync(cancellationToken);
            var family = Guid.NewGuid();

            await fixture.SeedAsync("ROTATEDOLD", family, expiresAt: Now.AddDays(-10), revokedAt: Now.AddDays(-40), hasReplacement: true, cancellationToken: cancellationToken);
            await fixture.SeedAsync("LIVE", family, expiresAt: Now.AddDays(10), cancellationToken: cancellationToken);

            var deleted = await fixture.Store.DeleteInactiveAsync(Now, Retention, 100, cancellationToken);

            Assert.Equal(1, deleted);
            Assert.Null(await fixture.Store.FindByHashAsync(StoreFixture.Hash("ROTATEDOLD"), cancellationToken));
            Assert.NotNull(await fixture.Store.FindByHashAsync(StoreFixture.Hash("LIVE"), cancellationToken));
        }

        [Fact]
        public async Task DeleteInactiveAsync_DeletesAtMostOneBatchPerCall() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var fixture = await StoreFixture.CreateAsync(cancellationToken);
            for(var i = 0; i < 5; i++)
                await fixture.SeedAsync($"OLD{i}", expiresAt: Now.AddDays(-90), revokedAt: Now.AddDays(-60), cancellationToken: cancellationToken);
            await fixture.SeedAsync("ACTIVE", expiresAt: Now.AddDays(10), cancellationToken: cancellationToken);

            var counts = new List<int>();
            int deleted;
            do {
                deleted = await fixture.Store.DeleteInactiveAsync(Now, Retention, 2, cancellationToken);
                counts.Add(deleted);
            } while(deleted > 0);

            Assert.Equal(new[] { 2, 2, 1, 0 }, counts);
            Assert.Equal(new[] { "ACTIVE" }, await fixture.RemainingHashPrefixesAsync(cancellationToken));
        }

        [Fact]
        public async Task DeleteInactiveAsync_WithNothingToDelete_ReturnsZero() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var fixture = await StoreFixture.CreateAsync(cancellationToken);

            Assert.Equal(0, await fixture.Store.DeleteInactiveAsync(Now, Retention, 10, cancellationToken));
        }

        [Fact]
        public async Task DeleteInactiveAsync_ZeroRetention_NeverDeletesATokenThatIsStillValid() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var fixture = await StoreFixture.CreateAsync(cancellationToken);
            await fixture.SeedAsync("ACTIVE", expiresAt: Now.AddMinutes(1), cancellationToken: cancellationToken);
            await fixture.SeedAsync("JUSTEXPIRED", expiresAt: Now.AddMinutes(-1), cancellationToken: cancellationToken);

            var deleted = await fixture.Store.DeleteInactiveAsync(Now, TimeSpan.Zero, 10, cancellationToken);

            Assert.Equal(1, deleted);
            Assert.Equal(new[] { "ACTIVE" }, await fixture.RemainingHashPrefixesAsync(cancellationToken));
        }

        [Fact]
        public async Task DeleteInactiveAsync_RejectsInvalidArguments() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var fixture = await StoreFixture.CreateAsync(cancellationToken);

            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
                fixture.Store.DeleteInactiveAsync(Now, TimeSpan.FromDays(-1), 10, cancellationToken));
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
                fixture.Store.DeleteInactiveAsync(Now, Retention, 0, cancellationToken));
        }

        // ---- service ----------------------------------------------------------------------------------

        [Fact]
        public async Task CleanupAsync_PassesCurrentTimeRetentionAndBatchSizeToTheStore() {
            var cancellationToken = TestContext.Current.CancellationToken;
            var store = new Mock<IRefreshTokenStore<string>>();
            var cleanup = store.As<IRefreshTokenCleanupStore<string>>();
            cleanup.Setup(s => s.DeleteInactiveAsync(Now, TimeSpan.FromDays(45), 250, cancellationToken)).ReturnsAsync(7);
            var service = new RefreshTokenCleanupService<string>(store.Object, Options.Create(new RefreshTokenOptions {
                CleanupRetention = TimeSpan.FromDays(45),
                CleanupBatchSize = 250
            }), new FixedTimeProvider(Now));

            Assert.Equal(7, await service.CleanupAsync(cancellationToken));
            cleanup.Verify(s => s.DeleteInactiveAsync(Now, TimeSpan.FromDays(45), 250, cancellationToken), Times.Once);
        }

        [Fact]
        public async Task CleanupAsync_StoreWithoutCleanupSupport_ThrowsActionableException() {
            var store = new Mock<IRefreshTokenStore<string>>();
            var service = new RefreshTokenCleanupService<string>(store.Object, Options.Create(new RefreshTokenOptions()), new FixedTimeProvider(Now));

            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                service.CleanupAsync(TestContext.Current.CancellationToken));
            Assert.Contains("IRefreshTokenCleanupStore", exception.Message);
        }

        [Fact]
        public async Task CleanupAsync_WithEfStore_AppliesRetentionAndBatchSizeFromOptions() {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var fixture = await StoreFixture.CreateAsync(cancellationToken);
            await fixture.SeedAsync("OLD1", expiresAt: Now.AddDays(-90), revokedAt: Now.AddDays(-60), cancellationToken: cancellationToken);
            await fixture.SeedAsync("OLD2", expiresAt: Now.AddDays(-90), revokedAt: Now.AddDays(-60), cancellationToken: cancellationToken);
            await fixture.SeedAsync("RECENT", expiresAt: Now.AddDays(-5), revokedAt: Now.AddDays(-5), cancellationToken: cancellationToken);
            var service = new RefreshTokenCleanupService<int>(fixture.Store, Options.Create(new RefreshTokenOptions {
                CleanupRetention = Retention,
                CleanupBatchSize = 1
            }), new FixedTimeProvider(Now));

            Assert.Equal(1, await service.CleanupAsync(cancellationToken));
            Assert.Equal(1, await service.CleanupAsync(cancellationToken));
            Assert.Equal(0, await service.CleanupAsync(cancellationToken));
            Assert.Equal(new[] { "RECENT" }, await fixture.RemainingHashPrefixesAsync(cancellationToken));
        }

        // ---- options and registration -----------------------------------------------------------------

        [Fact]
        public void CleanupOptions_HaveSafeDefaults() {
            using var provider = BuildProvider(_ => { });
            var options = provider.GetRequiredService<IOptions<RefreshTokenOptions>>().Value;

            Assert.Equal(TimeSpan.FromDays(30), options.CleanupRetention);
            Assert.Equal(1000, options.CleanupBatchSize);
            Assert.True(options.CleanupRetention >= options.TokenLifetime);
        }

        [Fact]
        public void CleanupOptions_RetentionBelowTokenLifetimeFailsValidation() {
            using var provider = BuildProvider(options => {
                options.TokenLifetime = TimeSpan.FromDays(30);
                options.CleanupRetention = TimeSpan.FromDays(29);
            });
            Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<RefreshTokenOptions>>().Value);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(10001)]
        public void CleanupOptions_BatchSizeOutsideAllowedRangeFailsValidation(int batchSize) {
            using var provider = BuildProvider(options => options.CleanupBatchSize = batchSize);
            Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<RefreshTokenOptions>>().Value);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(10000)]
        public void CleanupOptions_BatchSizeAtTheBoundsIsAccepted(int batchSize) {
            using var provider = BuildProvider(options => options.CleanupBatchSize = batchSize);
            Assert.Equal(batchSize, provider.GetRequiredService<IOptions<RefreshTokenOptions>>().Value.CleanupBatchSize);
        }

        [Fact]
        public void AddRefreshToken_RegistersCleanupServiceOnlyWhenRefreshTokensAreEnabled() {
            var without = new ServiceCollection();
            without.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();
            using var withoutProvider = without.BuildServiceProvider();
            Assert.False(withoutProvider.GetRequiredService<IServiceProviderIsService>().IsService(typeof(IRefreshTokenCleanupService<string>)));

            using var withProvider = BuildProvider(_ => { });
            Assert.True(withProvider.GetRequiredService<IServiceProviderIsService>().IsService(typeof(IRefreshTokenCleanupService<string>)));
        }

        private static ServiceProvider BuildProvider(Action<RefreshTokenOptions> configure) {
            var services = new ServiceCollection();
            services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
                .AddRefreshToken(configure);
            return services.BuildServiceProvider();
        }

        private sealed class FixedTimeProvider(DateTimeOffset now): TimeProvider {
            public override DateTimeOffset GetUtcNow() => now;
        }

        private sealed class StoreFixture: IAsyncDisposable {
            private readonly SqliteConnection _connection;
            private readonly TestDbContext _dbContext;

            private StoreFixture(SqliteConnection connection, TestDbContext dbContext) {
                _connection = connection;
                _dbContext = dbContext;
                Store = new EfRefreshTokenStore<TestDbContext, int>(dbContext);
            }

            public EfRefreshTokenStore<TestDbContext, int> Store { get; }

            public static async Task<StoreFixture> CreateAsync(CancellationToken cancellationToken) {
                var connection = new SqliteConnection("Data Source=:memory:");
                await connection.OpenAsync(cancellationToken);
                var options = new DbContextOptionsBuilder<TestDbContext>().UseSqlite(connection).Options;
                var dbContext = new TestDbContext(options);
                await dbContext.Database.EnsureCreatedAsync(cancellationToken);
                return new StoreFixture(connection, dbContext);
            }

            public static string Hash(string prefix) => prefix.PadRight(64, '0');

            public Task SeedAsync(
                string hashPrefix,
                Guid? familyId = null,
                DateTimeOffset? expiresAt = null,
                DateTimeOffset? revokedAt = null,
                bool hasReplacement = false,
                CancellationToken cancellationToken = default) =>
                Store.CreateAsync(new RefreshToken<int> {
                    Id = default,
                    UserId = 10,
                    FamilyId = familyId ?? Guid.NewGuid(),
                    TokenHash = Hash(hashPrefix),
                    CreatedAt = Now.AddDays(-200),
                    ExpiresAt = expiresAt ?? Now.AddDays(10),
                    AbsoluteExpiresAt = Now.AddDays(300),
                    RevokedAt = revokedAt,
                    HasReplacement = hasReplacement
                }, cancellationToken);

            public async Task<string[]> RemainingHashPrefixesAsync(CancellationToken cancellationToken) {
                var hashes = await _dbContext.Set<RefreshToken<int>>()
                    .AsNoTracking()
                    .Select(token => token.TokenHash)
                    .ToListAsync(cancellationToken);
                return hashes.Select(hash => hash.TrimEnd('0')).ToArray();
            }

            public async ValueTask DisposeAsync() {
                await _dbContext.DisposeAsync();
                await _connection.DisposeAsync();
            }
        }

        private sealed class TestDbContext: IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int> {
            public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }

            protected override void OnModelCreating(ModelBuilder modelBuilder) {
                base.OnModelCreating(modelBuilder);
                modelBuilder.AddRefreshTokenEntity<int>();
            }
        }
    }
}
