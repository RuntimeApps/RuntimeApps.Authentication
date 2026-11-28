using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.EF.Features.TwoFactor.Configurations;
using RuntimeApps.Authentication.EF.Features.TwoFactor.Stores;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.TwoFactor.Services;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.Test;

/// <summary>
/// The real management service over the real EF challenge/ledger store (SQLite), with mocked Identity managers,
/// a switchable re-authentication result and recording fake methods.
/// </summary>
public sealed class TwoFactorManagementHarness : IAsyncDisposable {
    public static readonly DateTimeOffset Start = new(2026, 1, 1, 9, 0, 0, TimeSpan.Zero);
    private readonly SqliteConnection _connection;

    private TwoFactorManagementHarness(SqliteConnection connection, ManagementDbContext db, Action<TwoFactorOptions> configure) {
        _connection = connection;
        Db = db;
        Options = new TwoFactorOptions { Issuer = "Acme", UsedCodeRetention = TimeSpan.FromMinutes(10) };
        configure?.Invoke(Options);
        Store = new EfTwoFactorChallengeStore<ManagementDbContext, int>(db);

        TwoFactor.Setup(t => t.GetTwoFactorEnabledAsync(It.IsAny<IdentityUser<int>>())).ReturnsAsync(() => Enabled);
        TwoFactor.Setup(t => t.SetTwoFactorEnabledAsync(It.IsAny<IdentityUser<int>>(), It.IsAny<bool>()))
            .ReturnsAsync((IdentityUser<int> _, bool value) => { Enabled = value; return IdentityResult.Success; });
        Lockout.Setup(l => l.IsLockedOutAsync(It.IsAny<IdentityUser<int>>())).ReturnsAsync(() => LockedOut);
        Reauthenticator = new Mock<TwoFactorReauthenticator<IdentityUser<int>>>(
            Lockout.Object, Mock.Of<IUserPasswordManager<IdentityUser<int>>>(), Mock.Of<ISignInManager<IdentityUser<int>>>(),
            Mock.Of<IUserLoginManager<IdentityUser<int>>>(), Array.Empty<IExternalLoginProvider<IdentityUser<int>>>());
        Reauthenticator.Setup(r => r.IsReauthenticatedAsync(It.IsAny<IdentityUser<int>>(), It.IsAny<TwoFactorReauthenticationModel>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => Reauthenticated);

        Service = new TwoFactorManagementService<IdentityUser<int>, int>(
            [Authenticator, Other], TwoFactor.Object, Lockout.Object, Reauthenticator.Object, Store,
            Microsoft.Extensions.Options.Options.Create(Options), Clock);
    }

    public IdentityUser<int> User { get; } = new() { Id = 7, UserName = "alice" };
    public bool Enabled { get; set; }
    public bool LockedOut { get; set; }
    public bool Reauthenticated { get; set; } = true;
    public FakeTwoFactorMethod Authenticator { get; } = new("authenticator") { Enrolled = false, ValidCode = "123456" };
    public FakeTwoFactorMethod Other { get; } = new("sms", deliveryBased: true) { Enrolled = false, ValidCode = "654321" };
    public TestClock Clock { get; } = new(Start);
    public TwoFactorOptions Options { get; }
    public Mock<IUserTwoFactorManager<IdentityUser<int>>> TwoFactor { get; } = new();
    public Mock<IUserLockoutManager<IdentityUser<int>>> Lockout { get; } = new();
    public Mock<TwoFactorReauthenticator<IdentityUser<int>>> Reauthenticator { get; }
    public ManagementDbContext Db { get; }
    public EfTwoFactorChallengeStore<ManagementDbContext, int> Store { get; }
    public TwoFactorManagementService<IdentityUser<int>, int> Service { get; }
    public CancellationToken Token => TestContext.Current.CancellationToken;

    public static async Task<TwoFactorManagementHarness> CreateAsync(Action<TwoFactorOptions> configure = null) {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var db = new ManagementDbContext(new DbContextOptionsBuilder<ManagementDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        return new TwoFactorManagementHarness(connection, db, configure);
    }

    public void VerifyFailureCounted(Times times) =>
        Lockout.Verify(l => l.AccessFailedAsync(It.IsAny<IdentityUser<int>>()), times);

    public Task<int> LedgerCountAsync() => Db.Set<TwoFactorUsedCode<int>>().AsNoTracking().CountAsync(Token);

    public async ValueTask DisposeAsync() {
        await Db.DisposeAsync();
        await _connection.DisposeAsync();
    }

    public sealed class ManagementDbContext(DbContextOptions<ManagementDbContext> options) : DbContext(options) {
        protected override void OnModelCreating(ModelBuilder modelBuilder) => modelBuilder.AddTwoFactorChallengeEntity<int>();
    }
}
