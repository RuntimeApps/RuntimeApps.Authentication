using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.EF.DependencyInjection;
using RuntimeApps.Authentication.EF.Features.TwoFactor.Configurations;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.TwoFactor.Services;

namespace RuntimeApps.Authentication.Test;

/// <summary>The whole two-factor service graph resolved from a real container with real Identity and EF stores.</summary>
public class TwoFactorServiceGraphTest {
    private static async Task<(ServiceProvider Provider, SqliteConnection Connection)> BuildAsync(Action<IServiceCollection> configure = null) {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<GraphDbContext>(o => o.UseSqlite(connection));
        services.AddScoped(_ => Mock.Of<IAuthenticationSessionIssuer<IdentityUser<int>>>());
        services.AddAuthentication()
            .AddRuntimeAppsAuthentication<IdentityUser<int>, IdentityRole<int>, int>()
            .AddEfStores<GraphDbContext, IdentityUser<int>, IdentityRole<int>, int>()
            .AddTwoFactor(o => o.Issuer = "Acme");
        services.AddTwoFactorChallengeStore<GraphDbContext, int>();
        configure?.Invoke(services);
        return (services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = false }), connection);
    }

    [Fact]
    public async Task EveryTwoFactorService_ResolvesWithItsDependencies() {
        var (provider, connection) = await BuildAsync();
        await using var _ = provider;
        await using var __ = connection;
        using var scope = provider.CreateScope();
        var sp = scope.ServiceProvider;

        Assert.IsType<TwoFactorLoginService<IdentityUser<int>, int>>(sp.GetRequiredService<ITwoFactorLoginService<IdentityUser<int>>>());
        Assert.IsType<TwoFactorManagementService<IdentityUser<int>, int>>(sp.GetRequiredService<ITwoFactorManagementService<IdentityUser<int>>>());
        Assert.NotNull(sp.GetRequiredService<TwoFactorReauthenticator<IdentityUser<int>>>());
        Assert.NotNull(sp.GetRequiredService<TwoFactorAccountEligibility<IdentityUser<int>, int>>());
        Assert.NotNull(sp.GetRequiredService<ITwoFactorCleanupService<int>>());
        Assert.NotNull(sp.GetRequiredService<ITwoFactorRequestLimiter>());
        Assert.Contains(sp.GetServices<ITwoFactorMethod<IdentityUser<int>>>(), m => m.Name == "authenticator");
    }

    [Fact]
    public async Task ManagementService_EndToEnd_StatusReflectsTheRealStores() {
        var (provider, connection) = await BuildAsync();
        await using var _ = provider;
        await using var __ = connection;
        using var scope = provider.CreateScope();
        var sp = scope.ServiceProvider;
        await sp.GetRequiredService<GraphDbContext>().Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        var users = sp.GetRequiredService<UserManager<IdentityUser<int>>>();
        var user = new IdentityUser<int> { UserName = "alice", Email = "alice@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Passw0rd!x")).Succeeded);

        var status = await sp.GetRequiredService<ITwoFactorManagementService<IdentityUser<int>>>().GetStatusAsync(user, TestContext.Current.CancellationToken);

        Assert.False(status.Enabled);
        Assert.Equal(new TwoFactorMethodStatus("authenticator", false, false), Assert.Single(status.Methods));
    }

    [Fact]
    public async Task DeveloperSuppliedManagementService_IsKept() {
        var custom = Mock.Of<ITwoFactorManagementService<IdentityUser<int>>>();
        var (provider, connection) = await BuildAsync(services => services.AddScoped(_ => custom));
        await using var _ = provider;
        await using var __ = connection;
        using var scope = provider.CreateScope();

        Assert.Same(custom, scope.ServiceProvider.GetRequiredService<ITwoFactorManagementService<IdentityUser<int>>>());
    }

    private sealed class GraphDbContext(DbContextOptions<GraphDbContext> options)
        : IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int>(options) {
        protected override void OnModelCreating(ModelBuilder builder) {
            base.OnModelCreating(builder);
            builder.AddTwoFactorChallengeEntity<int>();
        }
    }
}
