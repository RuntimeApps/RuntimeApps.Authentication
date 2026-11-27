using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.EF.DependencyInjection;
using RuntimeApps.Authentication.EF.Features.TwoFactor.Configurations;
using RuntimeApps.Authentication.EF.Features.TwoFactor.Stores;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.TwoFactor.Services;

namespace RuntimeApps.Authentication.Test;

/// <summary>Relational (SQLite) tests for the two-factor challenge store, replay ledger and cleanup.</summary>
public class EfTwoFactorChallengeStoreTest {
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ---- challenges ----

    [Fact]
    public async Task Create_PersistsChallengeAndFindsItByHashOnly() {
        await using var fixture = await Fixture.CreateAsync();

        await fixture.Store.CreateAsync(NewChallenge(10, "hash-a"), 5, fixture.Token);

        var found = await fixture.Store.FindByHandleHashAsync("hash-a", fixture.Token);
        Assert.NotNull(found);
        Assert.True(found.Id > 0);
        Assert.Equal(10, found.UserId);
        Assert.Equal(TwoFactorChallengeStatus.Pending, found.Status);
        Assert.Equal(0, found.Attempts);
        Assert.Null(await fixture.Store.FindByHandleHashAsync("hash-unknown", fixture.Token));
    }

    [Fact]
    public async Task Create_DuplicateHandleHash_IsRejectedAndLeavesContextUsable() {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.Store.CreateAsync(NewChallenge(10, "same"), 5, fixture.Token);

        await Assert.ThrowsAsync<DbUpdateException>(() => fixture.Store.CreateAsync(NewChallenge(10, "same"), 5, fixture.Token));

        await fixture.Store.CreateAsync(NewChallenge(10, "other"), 5, fixture.Token);
        Assert.Equal(2, await fixture.Db.Set<TwoFactorChallenge<int>>().AsNoTracking().CountAsync(fixture.Token));
    }

    [Fact]
    public async Task Create_ExceedingPendingCap_SupersedesOldestOnly() {
        await using var fixture = await Fixture.CreateAsync();
        for(var i = 1; i <= 5; i++)
            await fixture.Store.CreateAsync(NewChallenge(10, $"h{i}", Now.AddSeconds(i)), 3, fixture.Token);
        await fixture.Store.CreateAsync(NewChallenge(20, "other-user", Now.AddSeconds(1)), 3, fixture.Token);

        var statuses = (await fixture.Db.Set<TwoFactorChallenge<int>>().AsNoTracking().ToListAsync(fixture.Token))
            .ToDictionary(c => c.HandleHash, c => c.Status);

        Assert.Equal(TwoFactorChallengeStatus.Superseded, statuses["h1"]);
        Assert.Equal(TwoFactorChallengeStatus.Superseded, statuses["h2"]);
        Assert.Equal(TwoFactorChallengeStatus.Pending, statuses["h3"]);
        Assert.Equal(TwoFactorChallengeStatus.Pending, statuses["h4"]);
        Assert.Equal(TwoFactorChallengeStatus.Pending, statuses["h5"]);
        Assert.Equal(TwoFactorChallengeStatus.Pending, statuses["other-user"]);
    }

    [Fact]
    public async Task Create_ExpiredPendingChallengesDoNotCountTowardsCap() {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.Store.CreateAsync(NewChallenge(10, "old", Now, TimeSpan.FromMinutes(1)), 1, fixture.Token);

        await fixture.Store.CreateAsync(NewChallenge(10, "new", Now.AddMinutes(2)), 1, fixture.Token);

        var old = await fixture.Store.FindByHandleHashAsync("old", fixture.Token);
        Assert.Equal(TwoFactorChallengeStatus.Pending, old.Status); // expired, so untouched; it cannot be answered anyway
        Assert.False(await fixture.Store.TryReserveAttemptAsync(old.Id, 5, Now.AddMinutes(2), fixture.Token));
    }

    [Fact]
    public async Task ReserveAttempt_StopsAtMaximum_AndCorrectLastAttemptCanStillBeConsumed() {
        await using var fixture = await Fixture.CreateAsync();
        var id = await CreateAndGetIdAsync(fixture, 10, "h");

        for(var i = 0; i < 3; i++)
            Assert.True(await fixture.Store.TryReserveAttemptAsync(id, 3, Now.AddSeconds(1), fixture.Token));
        Assert.False(await fixture.Store.TryReserveAttemptAsync(id, 3, Now.AddSeconds(1), fixture.Token));

        Assert.True(await fixture.Store.TryConsumeAsync(id, Now.AddSeconds(2), fixture.Token));
        Assert.Equal(3, (await fixture.Store.FindByHandleHashAsync("h", fixture.Token)).Attempts);
    }

    [Fact]
    public async Task ReserveAttempt_FailsForExpiredConsumedAndSupersededChallenges() {
        await using var fixture = await Fixture.CreateAsync();
        var expired = await CreateAndGetIdAsync(fixture, 10, "expired", Now, TimeSpan.FromMinutes(1));
        var consumed = await CreateAndGetIdAsync(fixture, 11, "consumed");
        Assert.True(await fixture.Store.TryConsumeAsync(consumed, Now.AddSeconds(1), fixture.Token));
        var superseded = await CreateAndGetIdAsync(fixture, 12, "superseded", Now);
        await fixture.Store.CreateAsync(NewChallenge(12, "replacement", Now.AddSeconds(1)), 1, fixture.Token);

        Assert.False(await fixture.Store.TryReserveAttemptAsync(expired, 5, Now.AddMinutes(1), fixture.Token));
        Assert.False(await fixture.Store.TryReserveAttemptAsync(consumed, 5, Now.AddSeconds(2), fixture.Token));
        Assert.False(await fixture.Store.TryReserveAttemptAsync(superseded, 5, Now.AddSeconds(2), fixture.Token));
    }

    [Fact]
    public async Task Consume_SucceedsOnceOnly_AndNotAfterExpiryOrSupersede() {
        await using var fixture = await Fixture.CreateAsync();
        var id = await CreateAndGetIdAsync(fixture, 10, "h");
        var expired = await CreateAndGetIdAsync(fixture, 11, "e", Now, TimeSpan.FromMinutes(1));
        var superseded = await CreateAndGetIdAsync(fixture, 12, "s", Now);
        await fixture.Store.CreateAsync(NewChallenge(12, "s2", Now.AddSeconds(1)), 1, fixture.Token);

        Assert.True(await fixture.Store.TryConsumeAsync(id, Now.AddSeconds(1), fixture.Token));
        Assert.False(await fixture.Store.TryConsumeAsync(id, Now.AddSeconds(2), fixture.Token));
        Assert.False(await fixture.Store.TryConsumeAsync(expired, Now.AddMinutes(1), fixture.Token));
        Assert.False(await fixture.Store.TryConsumeAsync(superseded, Now.AddSeconds(2), fixture.Token));
        var completed = await fixture.Store.FindByHandleHashAsync("h", fixture.Token);
        Assert.Equal(TwoFactorChallengeStatus.Completed, completed.Status);
        Assert.NotNull(completed.CompletedAt);
    }

    [Fact]
    public async Task ReserveAttempt_ParallelGuesses_NeverExceedMaximum() {
        await using var file = new FileDatabase();
        var id = await file.SetupAsync(async store => {
            await store.CreateAsync(NewChallenge(10, "h"), 5);
            return (await store.FindByHandleHashAsync("h")).Id;
        });

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => file.RunAsync(store =>
            store.TryReserveAttemptAsync(id, 3, Now.AddSeconds(1)))));

        Assert.Equal(3, results.Count(r => r));
        Assert.Equal(3, await file.SetupAsync(async store => (await store.FindByHandleHashAsync("h")).Attempts));
    }

    [Fact]
    public async Task Consume_Parallel_OnlyOneSucceeds() {
        await using var file = new FileDatabase();
        var id = await file.SetupAsync(async store => {
            await store.CreateAsync(NewChallenge(10, "h"), 5);
            return (await store.FindByHandleHashAsync("h")).Id;
        });

        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => file.RunAsync(store =>
            store.TryConsumeAsync(id, Now.AddSeconds(1)))));

        Assert.Single(results, r => r);
    }

    // ---- ledger ----

    [Fact]
    public async Task MarkCodeUsed_SecondUseOfSameCodeIsRejected() {
        await using var fixture = await Fixture.CreateAsync();

        Assert.True(await fixture.Store.TryMarkCodeUsedAsync(10, "authenticator", "H1", Now, Now.AddMinutes(10), fixture.Token));
        Assert.False(await fixture.Store.TryMarkCodeUsedAsync(10, "authenticator", "H1", Now.AddSeconds(30), Now.AddMinutes(10), fixture.Token));

        Assert.Equal(1, await fixture.Db.Set<TwoFactorUsedCode<int>>().AsNoTracking().CountAsync(fixture.Token));
    }

    [Fact]
    public async Task MarkCodeUsed_IsScopedByUserMethodAndCode() {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True(await fixture.Store.TryMarkCodeUsedAsync(10, "authenticator", "H1", Now, Now.AddMinutes(10), fixture.Token));

        Assert.True(await fixture.Store.TryMarkCodeUsedAsync(11, "authenticator", "H1", Now, Now.AddMinutes(10), fixture.Token));
        Assert.True(await fixture.Store.TryMarkCodeUsedAsync(10, "sms", "H1", Now, Now.AddMinutes(10), fixture.Token));
        Assert.True(await fixture.Store.TryMarkCodeUsedAsync(10, "authenticator", "H2", Now, Now.AddMinutes(10), fixture.Token));
    }

    [Fact]
    public async Task MarkCodeUsed_AfterEntryExpires_CodeCanBeRecordedAgain() {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True(await fixture.Store.TryMarkCodeUsedAsync(10, "authenticator", "H1", Now, Now.AddMinutes(10), fixture.Token));

        Assert.False(await fixture.Store.TryMarkCodeUsedAsync(10, "authenticator", "H1", Now.AddMinutes(9), Now.AddMinutes(19), fixture.Token));
        Assert.True(await fixture.Store.TryMarkCodeUsedAsync(10, "authenticator", "H1", Now.AddMinutes(10), Now.AddMinutes(20), fixture.Token));
        Assert.Equal(1, await fixture.Db.Set<TwoFactorUsedCode<int>>().AsNoTracking().CountAsync(fixture.Token));
    }

    [Fact]
    public async Task MarkCodeUsed_ParallelSubmissionsOfSameCode_OnlyOneIsAccepted() {
        await using var file = new FileDatabase();
        await file.SetupAsync(_ => Task.FromResult(0));

        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => file.RunAsync(store =>
            store.TryMarkCodeUsedAsync(10, "authenticator", "H1", Now, Now.AddMinutes(10)))));

        Assert.Single(results, r => r);
    }

    // ---- cleanup ----

    [Fact]
    public async Task DeleteExpired_RemovesOnlyExpiredLedgerEntriesAndChallengesPastRetention() {
        await using var fixture = await Fixture.CreateAsync();
        var retention = TimeSpan.FromHours(1);
        await fixture.Store.CreateAsync(NewChallenge(1, "old", Now, TimeSpan.FromMinutes(5)), 9, fixture.Token);                   // expired 55m before cutoff
        await fixture.Store.CreateAsync(NewChallenge(2, "recent", Now.AddHours(2), TimeSpan.FromMinutes(5)), 9, fixture.Token);   // expired but inside retention
        await fixture.Store.CreateAsync(NewChallenge(3, "live", Now.AddHours(3), TimeSpan.FromMinutes(5)), 9, fixture.Token);     // still answerable
        await fixture.Store.TryMarkCodeUsedAsync(1, "authenticator", "OLD", Now, Now.AddMinutes(10), fixture.Token);
        await fixture.Store.TryMarkCodeUsedAsync(1, "authenticator", "LIVE", Now.AddHours(3), Now.AddHours(3).AddMinutes(10), fixture.Token);
        var cleanupNow = Now.AddHours(3).AddMinutes(1);

        var deleted = await fixture.Store.DeleteExpiredAsync(cleanupNow, retention, 100, fixture.Token);

        Assert.Equal(2, deleted); // OLD ledger entry + "old" challenge
        Assert.Null(await fixture.Store.FindByHandleHashAsync("old", fixture.Token));
        Assert.NotNull(await fixture.Store.FindByHandleHashAsync("recent", fixture.Token));
        Assert.NotNull(await fixture.Store.FindByHandleHashAsync("live", fixture.Token));
        Assert.False(await fixture.Store.TryMarkCodeUsedAsync(1, "authenticator", "LIVE", cleanupNow, cleanupNow.AddMinutes(10), fixture.Token));
    }

    [Fact]
    public async Task DeleteExpired_NeverDeletesMoreThanBatchSize() {
        await using var fixture = await Fixture.CreateAsync();
        for(var i = 0; i < 4; i++) {
            await fixture.Store.CreateAsync(NewChallenge(100 + i, $"c{i}", Now, TimeSpan.FromMinutes(1)), 9, fixture.Token);
            await fixture.Store.TryMarkCodeUsedAsync(100 + i, "authenticator", $"L{i}", Now, Now.AddMinutes(1), fixture.Token);
        }
        var later = Now.AddDays(1);

        Assert.Equal(3, await fixture.Store.DeleteExpiredAsync(later, TimeSpan.Zero, 3, fixture.Token));
        Assert.Equal(3, await fixture.Store.DeleteExpiredAsync(later, TimeSpan.Zero, 3, fixture.Token));
        Assert.Equal(2, await fixture.Store.DeleteExpiredAsync(later, TimeSpan.Zero, 3, fixture.Token));
        Assert.Equal(0, await fixture.Store.DeleteExpiredAsync(later, TimeSpan.Zero, 3, fixture.Token));
    }

    [Fact]
    public async Task DeleteExpired_RejectsInvalidArguments() {
        await using var fixture = await Fixture.CreateAsync();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => fixture.Store.DeleteExpiredAsync(Now, TimeSpan.FromSeconds(-1), 10, fixture.Token));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => fixture.Store.DeleteExpiredAsync(Now, TimeSpan.Zero, 0, fixture.Token));
    }

    [Fact]
    public async Task CleanupService_PassesTimeRetentionAndBatchSizeFromOptions() {
        var store = new Mock<ITwoFactorChallengeStore<int>>();
        var cleanup = store.As<ITwoFactorCleanupStore<int>>();
        cleanup.Setup(c => c.DeleteExpiredAsync(Now, TimeSpan.FromMinutes(90), 250, It.IsAny<CancellationToken>())).ReturnsAsync(7);
        var service = new TwoFactorCleanupService<int>(store.Object,
            Options.Create(new TwoFactorOptions { Issuer = "Acme", CleanupRetention = TimeSpan.FromMinutes(90), CleanupBatchSize = 250 }),
            new FixedTimeProvider(Now));

        Assert.Equal(7, await service.CleanupAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CleanupService_StoreWithoutCleanupSupport_ThrowsActionableException() {
        var service = new TwoFactorCleanupService<int>(Mock.Of<ITwoFactorChallengeStore<int>>(),
            Options.Create(new TwoFactorOptions { Issuer = "Acme" }), new FixedTimeProvider(Now));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.CleanupAsync(TestContext.Current.CancellationToken));
        Assert.Contains("ITwoFactorCleanupStore", exception.Message);
    }

    // ---- model, registration, hashing, options ----

    [Fact]
    public void Store_RejectsDbContextWithoutTwoFactorEntities() {
        using var connection = new SqliteConnection("Data Source=:memory:");
        using var db = new PlainContext(new DbContextOptionsBuilder<PlainContext>().UseSqlite(connection).Options);

        var exception = Assert.Throws<InvalidOperationException>(() => new EfTwoFactorChallengeStore<PlainContext, int>(db));
        Assert.Contains("AddTwoFactorChallengeEntity", exception.Message);
    }

    [Fact]
    public async Task Registration_ResolvesEfStoreAndCleanupService() {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<StoreContext>(o => o.UseSqlite(connection));
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser<int>, IdentityRole<int>, int>()
            .AddEfStores<StoreContext, IdentityUser<int>, IdentityRole<int>, int>()
            .AddTwoFactor(o => o.Issuer = "Acme");
        services.AddTwoFactorChallengeStore<StoreContext, int>();

        await using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope = provider.CreateScope();

        var store = scope.ServiceProvider.GetRequiredService<ITwoFactorChallengeStore<int>>();
        Assert.IsType<EfTwoFactorChallengeStore<StoreContext, int>>(store);
        Assert.IsType<TwoFactorCleanupService<int>>(scope.ServiceProvider.GetRequiredService<ITwoFactorCleanupService<int>>());
    }

    [Fact]
    public void CodeHash_IsStableHexAndDoesNotContainTheCode() {
        var hash = TwoFactorCodeHash.Compute("42", "authenticator", "123456");

        Assert.Equal(hash, TwoFactorCodeHash.Compute("42", "authenticator", "123456"));
        Assert.Equal(64, hash.Length);
        Assert.Matches("^[0-9A-F]{64}$", hash);
        Assert.DoesNotContain("123456", hash);
    }

    [Fact]
    public void CodeHash_DiffersByUserMethodAndCode_AndCannotBeConfusedByDelimiters() {
        var baseline = TwoFactorCodeHash.Compute("42", "authenticator", "123456");

        Assert.NotEqual(baseline, TwoFactorCodeHash.Compute("43", "authenticator", "123456"));
        Assert.NotEqual(baseline, TwoFactorCodeHash.Compute("42", "sms", "123456"));
        Assert.NotEqual(baseline, TwoFactorCodeHash.Compute("42", "authenticator", "123457"));
        Assert.NotEqual(TwoFactorCodeHash.Compute("a|b", "c", "123456"), TwoFactorCodeHash.Compute("a", "b|c", "123456"));
    }

    [Fact]
    public void CodeHash_RejectsEmptyInput() {
        Assert.Throws<ArgumentException>(() => TwoFactorCodeHash.Compute("", "authenticator", "123456"));
        Assert.Throws<ArgumentException>(() => TwoFactorCodeHash.Compute("42", "", "123456"));
        Assert.Throws<ArgumentException>(() => TwoFactorCodeHash.Compute("42", "authenticator", ""));
    }

    [Fact]
    public void RetentionOptions_HaveSafeDefaultsAndBounds() {
        var options = new TwoFactorOptions { Issuer = "Acme" };
        options.Validate();

        Assert.Equal(TimeSpan.FromMinutes(10), options.UsedCodeRetention);
        Assert.Equal(TimeSpan.FromHours(1), options.CleanupRetention);
        Assert.Equal(1000, options.CleanupBatchSize);
        Assert.Throws<InvalidOperationException>(() => new TwoFactorOptions { Issuer = "Acme", UsedCodeRetention = TimeSpan.FromMinutes(2) }.Validate());
        Assert.Throws<InvalidOperationException>(() => new TwoFactorOptions { Issuer = "Acme", UsedCodeRetention = TimeSpan.FromDays(2) }.Validate());
        Assert.Throws<InvalidOperationException>(() => new TwoFactorOptions { Issuer = "Acme", CleanupRetention = TimeSpan.FromSeconds(-1) }.Validate());
        Assert.Throws<InvalidOperationException>(() => new TwoFactorOptions { Issuer = "Acme", CleanupBatchSize = 0 }.Validate());
        Assert.Throws<InvalidOperationException>(() => new TwoFactorOptions { Issuer = "Acme", CleanupBatchSize = 10001 }.Validate());
    }

    // ---- helpers ----

    private static TwoFactorChallenge<int> NewChallenge(int userId, string hash, DateTimeOffset? createdAt = null, TimeSpan? lifetime = null) {
        var created = createdAt ?? Now;
        return new TwoFactorChallenge<int> {
            UserId = userId, HandleHash = hash, Status = TwoFactorChallengeStatus.Pending,
            CreatedAt = created, ExpiresAt = created + (lifetime ?? TimeSpan.FromMinutes(5))
        };
    }

    private static async Task<int> CreateAndGetIdAsync(Fixture fixture, int userId, string hash, DateTimeOffset? createdAt = null, TimeSpan? lifetime = null) {
        await fixture.Store.CreateAsync(NewChallenge(userId, hash, createdAt, lifetime), 9, fixture.Token);
        return (await fixture.Store.FindByHandleHashAsync(hash, fixture.Token)).Id;
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class Fixture : IAsyncDisposable {
        private readonly SqliteConnection _connection;
        private Fixture(SqliteConnection connection, StoreContext db) {
            _connection = connection;
            Db = db;
            Store = new EfTwoFactorChallengeStore<StoreContext, int>(db);
        }
        public StoreContext Db { get; }
        public EfTwoFactorChallengeStore<StoreContext, int> Store { get; }
        public CancellationToken Token => TestContext.Current.CancellationToken;

        public static async Task<Fixture> CreateAsync() {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            var db = new StoreContext(new DbContextOptionsBuilder<StoreContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            return new Fixture(connection, db);
        }

        public async ValueTask DisposeAsync() {
            await Db.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }

    /// <summary>File-backed database so each parallel operation gets its own connection and context.</summary>
    private sealed class FileDatabase : IAsyncDisposable {
        private readonly string _path = Path.Combine(Path.GetTempPath(), $"runtimeapps-2fa-{Guid.NewGuid():N}.db");
        private bool _created;

        private StoreContext CreateContext() =>
            new(new DbContextOptionsBuilder<StoreContext>().UseSqlite($"Data Source={_path};Pooling=False").Options);

        public async Task<T> SetupAsync<T>(Func<EfTwoFactorChallengeStore<StoreContext, int>, Task<T>> action) {
            await using var db = CreateContext();
            if(!_created) {
                await db.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
                _created = true;
            }
            return await action(new EfTwoFactorChallengeStore<StoreContext, int>(db));
        }

        public Task<T> RunAsync<T>(Func<EfTwoFactorChallengeStore<StoreContext, int>, Task<T>> action) => Task.Run(async () => {
            await using var db = CreateContext();
            return await action(new EfTwoFactorChallengeStore<StoreContext, int>(db));
        }, TestContext.Current.CancellationToken);

        public ValueTask DisposeAsync() {
            SqliteConnection.ClearAllPools();
            if(File.Exists(_path)) File.Delete(_path);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class StoreContext(DbContextOptions<StoreContext> options)
        : IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int>(options) {
        protected override void OnModelCreating(ModelBuilder modelBuilder) {
            base.OnModelCreating(modelBuilder);
            modelBuilder.AddTwoFactorChallengeEntity<int>();
        }
    }

    private sealed class PlainContext(DbContextOptions<PlainContext> options) : DbContext(options);
}
