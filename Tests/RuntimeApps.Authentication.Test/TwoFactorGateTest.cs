using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.EF.DependencyInjection;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.Test;

/// <summary>Verifies the sign-in manager's two-factor gate with real Identity, EF and sign-in services.</summary>
public class TwoFactorGateTest {
    private const string Password = "Passw0rd!Test";

    [Fact]
    public async Task WithTwoFactor_FlaggedUserWithoutEnrolledMethod_StillRequiresSecondStep() {
        await using var harness = await Harness.CreateAsync(withTwoFactor: true);
        var user = await harness.CreateUserAsync(twoFactorEnabled: true);

        var result = await harness.SignIn.PasswordSignInAsync(user, Password, false, true);

        Assert.True(result.RequiresTwoFactor);
        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task WithTwoFactor_FlaggedUserWithEnrolledAuthenticator_RequiresSecondStep() {
        await using var harness = await Harness.CreateAsync(withTwoFactor: true);
        var user = await harness.CreateUserAsync(twoFactorEnabled: true);
        await harness.Users.ResetAuthenticatorKeyAsync(user);

        var result = await harness.SignIn.PasswordSignInAsync(user, Password, false, true);

        Assert.True(result.RequiresTwoFactor);
    }

    [Fact]
    public async Task WithTwoFactor_UnflaggedUser_SignsInWithPassword() {
        await using var harness = await Harness.CreateAsync(withTwoFactor: true);
        var user = await harness.CreateUserAsync(twoFactorEnabled: false);

        var result = await harness.SignIn.PasswordSignInAsync(user, Password, false, true);

        Assert.True(result.Succeeded);
        Assert.False(result.RequiresTwoFactor);
    }

    [Fact]
    public async Task WithoutTwoFactor_LegacyGateIsUnchanged_FlaggedUserWithoutProviderSignsIn() {
        await using var harness = await Harness.CreateAsync(withTwoFactor: false);
        var user = await harness.CreateUserAsync(twoFactorEnabled: true);

        var result = await harness.SignIn.PasswordSignInAsync(user, Password, false, true);

        Assert.True(result.Succeeded);
        Assert.False(result.RequiresTwoFactor);
    }

    [Fact]
    public async Task WrongPassword_IsStillRejectedAndCountedWhenTwoFactorIsRegistered() {
        await using var harness = await Harness.CreateAsync(withTwoFactor: true);
        var user = await harness.CreateUserAsync(twoFactorEnabled: true);

        var result = await harness.SignIn.PasswordSignInAsync(user, "wrong-password", false, true);

        Assert.False(result.Succeeded);
        Assert.False(result.RequiresTwoFactor);
        Assert.Equal(1, await harness.Users.GetAccessFailedCountAsync(user));
    }

    [Fact]
    public async Task CorrectPassword_DoesNotResetFailedCount_ForUserWithEnrolledAuthenticator() {
        await using var harness = await Harness.CreateAsync(withTwoFactor: true);
        var user = await harness.CreateUserAsync(twoFactorEnabled: true);
        await harness.Users.ResetAuthenticatorKeyAsync(user);
        await harness.Users.AccessFailedAsync(user); // stands in for a wrong second-factor code

        var result = await harness.SignIn.PasswordSignInAsync(user, Password, false, true);

        Assert.True(result.RequiresTwoFactor);
        // Identity must not wipe the wrong-code count when the password is right but the second step is pending,
        // otherwise alternating password/code attempts could never reach lockout.
        Assert.Equal(1, await harness.Users.GetAccessFailedCountAsync(user));
    }

    [Fact]
    public async Task CorrectPassword_DoesNotResetFailedCount_ForFlaggedUserWithoutAnIdentityProvider() {
        // Stands in for a user enrolled only in a delivery method (SMS/email), which Identity does not know as a provider.
        await using var harness = await Harness.CreateAsync(withTwoFactor: true);
        var user = await harness.CreateUserAsync(twoFactorEnabled: true);
        await harness.Users.AccessFailedAsync(user);

        var result = await harness.SignIn.PasswordSignInAsync(user, Password, false, true);

        Assert.True(result.RequiresTwoFactor);
        Assert.Equal(1, await harness.Users.GetAccessFailedCountAsync(user));
    }

    [Fact]
    public async Task CorrectPassword_StillResetsFailedCount_ForUnflaggedUser() {
        await using var harness = await Harness.CreateAsync(withTwoFactor: true);
        var user = await harness.CreateUserAsync(twoFactorEnabled: false);
        await harness.Users.AccessFailedAsync(user);

        var result = await harness.SignIn.PasswordSignInAsync(user, Password, false, true);

        Assert.True(result.Succeeded);
        Assert.Equal(0, await harness.Users.GetAccessFailedCountAsync(user));
    }

    [Fact]
    public async Task WrongPasswords_StillLockOutFlaggedUser_AndLockedUserIsRejected() {
        await using var harness = await Harness.CreateAsync(withTwoFactor: true);
        var user = await harness.CreateUserAsync(twoFactorEnabled: true);

        SignInResult last = null;
        for(var i = 0; i < 5; i++)
            last = await harness.SignIn.PasswordSignInAsync(user, "wrong-password", false, true);

        Assert.True(last.IsLockedOut);
        var correctWhileLocked = await harness.SignIn.PasswordSignInAsync(user, Password, false, true);
        Assert.True(correctWhileLocked.IsLockedOut);
        Assert.False(correctWhileLocked.RequiresTwoFactor);
    }

    [Fact]
    public async Task WithoutTwoFactor_ResetBehaviorIsUnchanged() {
        await using var harness = await Harness.CreateAsync(withTwoFactor: false);
        var user = await harness.CreateUserAsync(twoFactorEnabled: true);
        await harness.Users.AccessFailedAsync(user);

        var result = await harness.SignIn.PasswordSignInAsync(user, Password, false, true);

        Assert.True(result.Succeeded);
        Assert.Equal(0, await harness.Users.GetAccessFailedCountAsync(user));
    }

    private sealed class Harness : IAsyncDisposable {
        private readonly SqliteConnection _connection;
        private readonly ServiceProvider _provider;
        private readonly IServiceScope _scope;

        private Harness(SqliteConnection connection, ServiceProvider provider) {
            _connection = connection;
            _provider = provider;
            _scope = provider.CreateScope();
            Users = _scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser<int>>>();
            SignIn = _scope.ServiceProvider.GetRequiredService<ISignInManager<IdentityUser<int>>>();
        }

        public UserManager<IdentityUser<int>> Users { get; }
        public ISignInManager<IdentityUser<int>> SignIn { get; }

        public static async Task<Harness> CreateAsync(bool withTwoFactor) {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddDbContext<GateDbContext>(o => o.UseSqlite(connection));
            var builder = services.AddAuthentication()
                .AddRuntimeAppsAuthentication<IdentityUser<int>, IdentityRole<int>, int>()
                .AddEfStores<GateDbContext, IdentityUser<int>, IdentityRole<int>, int>();
            if(withTwoFactor)
                builder.AddTwoFactor(o => o.Issuer = "Acme");
            var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
            var harness = new Harness(connection, provider);
            await harness._scope.ServiceProvider.GetRequiredService<GateDbContext>().Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            return harness;
        }

        public async Task<IdentityUser<int>> CreateUserAsync(bool twoFactorEnabled) {
            var user = new IdentityUser<int> { UserName = "alice", Email = "alice@example.com", EmailConfirmed = true };
            Assert.True((await Users.CreateAsync(user, Password)).Succeeded);
            if(twoFactorEnabled)
                Assert.True((await Users.SetTwoFactorEnabledAsync(user, true)).Succeeded);
            return user;
        }

        public async ValueTask DisposeAsync() {
            _scope.Dispose();
            await _provider.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }

    private sealed class GateDbContext(DbContextOptions<GateDbContext> options)
        : IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int>(options);
}
