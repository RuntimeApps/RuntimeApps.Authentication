using System.Globalization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.EF.Features.TwoFactor.Configurations;
using RuntimeApps.Authentication.EF.Features.TwoFactor.Stores;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.TwoFactor.Services;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

/// <summary>
/// Wires the real EF challenge store (SQLite) and the real login service to mocked Identity managers and a
/// recording session issuer, so security behavior can be asserted end to end without a web host.
/// </summary>
public sealed class TwoFactorLoginHarness : IAsyncDisposable {
    private readonly SqliteConnection _connection;

    private TwoFactorLoginHarness(SqliteConnection connection, LoginDbContext db, Action<TwoFactorOptions> configure) {
        _connection = connection;
        Db = db;
        Options = new TwoFactorOptions { Issuer = "Acme", UsedCodeRetention = TimeSpan.FromMinutes(10) };
        configure?.Invoke(Options);
        Store = new EfTwoFactorChallengeStore<LoginDbContext, int>(db);

        TwoFactor.Setup(t => t.GetTwoFactorEnabledAsync(It.IsAny<IdentityUser<int>>())).ReturnsAsync(true);
        Users.Setup(u => u.FindByIdAsync("7")).ReturnsAsync(() => UserExists ? User : null);
        Lockout.Setup(l => l.IsLockedOutAsync(It.IsAny<IdentityUser<int>>())).ReturnsAsync(() => LockedOut);
        Logins.Setup(l => l.GetLoginsAsync(It.IsAny<IdentityUser<int>>())).ReturnsAsync(new List<UserLoginInfo>());
        SignIn.Setup(s => s.CanSignInAsync(It.IsAny<IdentityUser<int>>())).ReturnsAsync(true);
        Issuer.Setup(i => i.IssueAsync(It.IsAny<IdentityUser<int>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Token { AuthenticationToken = "access-token" });

        Service = new TwoFactorLoginService<IdentityUser<int>, int>(
            Store, [Authenticator], Microsoft.Extensions.Options.Options.Create(Options), Clock,
            Users.Object, Lockout.Object,
            new TwoFactorAccountEligibility<IdentityUser<int>, int>(Lockout.Object, Logins.Object, SignIn.Object,
                Microsoft.Extensions.Options.Options.Create(new VerificationOptions())),
            Issuer.Object, TwoFactor.Object);
    }

    public static readonly DateTimeOffset Start = new(2026, 1, 1, 9, 0, 0, TimeSpan.Zero);

    public IdentityUser<int> User { get; } = new() { Id = 7, UserName = "alice", EmailConfirmed = true };
    public bool UserExists { get; set; } = true;
    public bool LockedOut { get; set; }
    public FakeTwoFactorMethod Authenticator { get; } = new("authenticator") { ValidCode = "123456" };
    public TestClock Clock { get; } = new(Start);
    public TwoFactorOptions Options { get; }
    public Mock<IUserManager<IdentityUser<int>>> Users { get; } = new();
    public Mock<IUserTwoFactorManager<IdentityUser<int>>> TwoFactor { get; } = new();
    public Mock<IUserLockoutManager<IdentityUser<int>>> Lockout { get; } = new();
    public Mock<IUserLoginManager<IdentityUser<int>>> Logins { get; } = new();
    public Mock<ISignInManager<IdentityUser<int>>> SignIn { get; } = new();
    public Mock<IAuthenticationSessionIssuer<IdentityUser<int>>> Issuer { get; } = new();
    public LoginDbContext Db { get; }
    public EfTwoFactorChallengeStore<LoginDbContext, int> Store { get; }
    public TwoFactorLoginService<IdentityUser<int>, int> Service { get; }
    public CancellationToken Token => TestContext.Current.CancellationToken;

    public static async Task<TwoFactorLoginHarness> CreateAsync(Action<TwoFactorOptions> configure = null) {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var db = new LoginDbContext(new DbContextOptionsBuilder<LoginDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        return new TwoFactorLoginHarness(connection, db, configure);
    }

    /// <summary>Runs the first-factor-succeeded step and returns the handle a client would hold.</summary>
    public async Task<string> StartChallengeAsync() => (await Service.BeginAsync(User, Token)).Challenge;

    public Task<Result<IdentityUser<int>, Token>> CompleteAsync(string challenge, string code = "123456", string method = "authenticator") =>
        Service.CompleteAsync(challenge, method, code, Token);

    public void VerifyNoSessionWasIssued() =>
        Issuer.Verify(i => i.IssueAsync(It.IsAny<IdentityUser<int>>(), It.IsAny<CancellationToken>()), Times.Never);

    public void VerifyFailureCounted(Times times) =>
        Lockout.Verify(l => l.AccessFailedAsync(It.IsAny<IdentityUser<int>>()), times);

    public Task<TwoFactorChallenge<int>> StoredChallengeAsync(string handle) =>
        Store.FindByHandleHashAsync(RuntimeApps.Authentication.Features.Verification.Services.VerificationHandle.ComputeHash(handle), Token);

    public Task<int> LedgerCountAsync() => Db.Set<TwoFactorUsedCode<int>>().AsNoTracking().CountAsync(Token);

    public async ValueTask DisposeAsync() {
        await Db.DisposeAsync();
        await _connection.DisposeAsync();
    }

    public sealed class LoginDbContext(DbContextOptions<LoginDbContext> options) : DbContext(options) {
        protected override void OnModelCreating(ModelBuilder modelBuilder) => modelBuilder.AddTwoFactorChallengeEntity<int>();
    }
}
