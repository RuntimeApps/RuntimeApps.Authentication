using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Moq;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;

namespace RuntimeApps.Authentication.Test;

public class TwoFactorDependenciesValidatorTest {
    [Fact]
    public async Task MissingChallengeStore_FailsStartupWithActionableMessage() {
        var provider = Build(addStore: false, addIssuer: true);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => RunAsync(provider));

        Assert.Contains("ITwoFactorChallengeStore", error.Message);
        Assert.Contains("AddTwoFactorChallengeStore", error.Message);
    }

    [Fact]
    public async Task MissingSessionIssuer_FailsStartupWithActionableMessage() {
        var provider = Build(addStore: true, addIssuer: false);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => RunAsync(provider));

        Assert.Contains("IAuthenticationSessionIssuer", error.Message);
    }

    [Fact]
    public async Task AllDependenciesPresent_StartsNormally() {
        var provider = Build(addStore: true, addIssuer: true);

        await RunAsync(provider);
    }

    [Fact]
    public void WithoutAddTwoFactor_NoDependencyValidatorIsRegistered() {
        var services = new ServiceCollection();
        services.AddSingleton<IUserStore<IdentityUser>>(Mock.Of<IUserStore<IdentityUser>>());
        services.AddSingleton<IRoleStore<IdentityRole>>(Mock.Of<IRoleStore<IdentityRole>>());
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();
        using var provider = services.BuildServiceProvider();

        Assert.DoesNotContain(provider.GetServices<IHostedService>(), IsValidator);
    }

    private static ServiceProvider Build(bool addStore, bool addIssuer) {
        var services = new ServiceCollection();
        services.AddSingleton<IUserStore<IdentityUser>>(Mock.Of<IUserStore<IdentityUser>>());
        services.AddSingleton<IRoleStore<IdentityRole>>(Mock.Of<IRoleStore<IdentityRole>>());
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
            .AddTwoFactor(o => o.Issuer = "Acme");
        if(addStore) services.AddScoped(_ => Mock.Of<ITwoFactorChallengeStore<string>>());
        if(addIssuer) services.AddScoped(_ => Mock.Of<IAuthenticationSessionIssuer<IdentityUser>>());
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    private static bool IsValidator(IHostedService service) =>
        service.GetType().Name.StartsWith("TwoFactorDependenciesStartupValidator", StringComparison.Ordinal);

    private static Task RunAsync(IServiceProvider provider) =>
        provider.GetServices<IHostedService>().Single(IsValidator).StartAsync(CancellationToken.None);
}
