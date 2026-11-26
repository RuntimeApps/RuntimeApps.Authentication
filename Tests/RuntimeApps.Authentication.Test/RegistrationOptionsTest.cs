using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
using RuntimeApps.Authentication.Features.ExternalLogin.Providers;
using RuntimeApps.Authentication.Features.PasswordRecovery.Contracts;
using RuntimeApps.Authentication.Features.PasswordRecovery.Models;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Features.Account.Contracts;

namespace RuntimeApps.Authentication.Test;

public class RegistrationOptionsTest {
    [Fact]
    public void VerificationConfiguration_CombinesBindingThenCodeOverrides() {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            [$"{VerificationOptions.SectionName}:CodeLength"] = "8",
            [$"{VerificationOptions.SectionName}:MaximumFailedAttempts"] = "9"
        }).Build();
        var services = new ServiceCollection();
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
            .AddVerificationServices(configuration)
            .AddVerificationServices(o => o.CodeLength = 10);

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<VerificationOptions>>().Value;
        Assert.Equal(10, options.CodeLength);
        Assert.Equal(9, options.MaximumFailedAttempts);
    }

    [Fact]
    public void CoreRegistration_DoesNotRegisterOptionalVerificationServices() {
        var services = new ServiceCollection();
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();
        using var provider = services.BuildServiceProvider();
        Assert.False(provider.GetRequiredService<IServiceProviderIsService>().IsService(typeof(Features.Verification.Contracts.IVerificationWorkflowService<IdentityUser, string>)));
        Assert.False(provider.GetRequiredService<IServiceProviderIsService>().IsService(typeof(IForgotPasswordService<IdentityUser, string>)));
        Assert.False(provider.GetRequiredService<IServiceProviderIsService>().IsService(typeof(RuntimeApps.Authentication.Features.RefreshTokens.Contracts.IRefreshTokenService<string>)));
        Assert.Empty(provider.GetServices<IExternalLoginProvider<IdentityUser>>());
    }

    [Fact]
    public void InvalidVerificationOptions_FailOptionsValidation() {
        var services = new ServiceCollection();
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
            .AddVerificationServices(options => options.CodeLength = 3);
        using var provider = services.BuildServiceProvider();
        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<VerificationOptions>>().Value);
    }

    [Fact]
    public void RefreshTokenOptions_DefaultAbsoluteSessionLifetimeIsNinetyDays() {
        var services = new ServiceCollection();
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
            .AddRefreshToken();
        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<RefreshTokenOptions>>().Value;
        Assert.Equal(TimeSpan.FromDays(90), options.AbsoluteSessionLifetime);
    }

    [Fact]
    public void RefreshTokenOptions_AbsoluteSessionLifetimeBelowTokenLifetimeFailsValidation() {
        var services = new ServiceCollection();
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
            .AddRefreshToken(options => {
                options.TokenLifetime = TimeSpan.FromDays(30);
                options.AbsoluteSessionLifetime = TimeSpan.FromDays(29);
            });
        using var provider = services.BuildServiceProvider();
        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<RefreshTokenOptions>>().Value);
    }

    [Fact]
    public void RefreshTokenOptions_TokenLifetimeAboveDefaultAbsoluteLifetimeFailsValidationUntilBothAreSet() {
        var failing = new ServiceCollection();
        failing.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
            .AddRefreshToken(options => {
                options.TokenLifetime = TimeSpan.FromDays(120);
                options.CleanupRetention = TimeSpan.FromDays(120);
            });
        using var failingProvider = failing.BuildServiceProvider();
        Assert.Throws<OptionsValidationException>(() => failingProvider.GetRequiredService<IOptions<RefreshTokenOptions>>().Value);

        var valid = new ServiceCollection();
        valid.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
            .AddRefreshToken(options => {
                options.TokenLifetime = TimeSpan.FromDays(120);
                options.AbsoluteSessionLifetime = TimeSpan.FromDays(120);
                options.CleanupRetention = TimeSpan.FromDays(120);
            });
        using var validProvider = valid.BuildServiceProvider();
        Assert.Equal(TimeSpan.FromDays(120), validProvider.GetRequiredService<IOptions<RefreshTokenOptions>>().Value.AbsoluteSessionLifetime);
    }

    [Fact]
    public void ExternalProviders_RegisterTogetherAndRepeatedCallsDoNotDuplicate() {
        var services = new ServiceCollection();
        var builder = services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();
        builder.AddGoogleExternalLogin(o => { o.ClientId = "google"; o.ClientSecret = "secret"; });
        builder.AddFacebookExternalLogin(o => { o.ClientId = "facebook"; o.ClientSecret = "secret"; });
        builder.AddMicrosoftExternalLogin(o => { o.ClientId = "microsoft"; o.ClientSecret = "secret"; });
        builder.AddGoogleExternalLogin(o => { o.ClientId = "google"; o.ClientSecret = "secret"; });
        using var provider = services.BuildServiceProvider();
        var providers = provider.GetServices<IExternalLoginProvider<IdentityUser>>().ToArray();
        Assert.Equal(3, providers.Length);
        Assert.Contains(providers, p => p is GoogleExternalLoginProvider<IdentityUser>);
        Assert.Contains(providers, p => p is FacebookExternalLoginProvider<IdentityUser>);
        Assert.Contains(providers, p => p is MicrosoftExternalLoginProvider<IdentityUser>);
    }

    [Fact]
    public void JwtOptions_AreIsolatedBySchemeForCodeAndConfiguration() {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Authentication:Jwt:SaveToken"] = "true",
            ["Authentication:Jwt:RequireHttpsMetadata"] = "false",
            ["Authentication:Jwt:RefreshOnIssuerKeyNotFound"] = "true",
            ["Authentication:Jwt:TokenValidationParameters:ValidAudience"] = "bound-audience"
        }).Build();
        var services = new ServiceCollection();
        var builder = services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();
        builder.UseJwt("configured", configuration, options => { options.SaveToken = false; options.RequireHttpsMetadata = true; });
        builder.UseJwt("code", options => { options.RequireHttpsMetadata = false; options.RefreshOnIssuerKeyNotFound = false; });

        using var provider = services.BuildServiceProvider();
        var optionsMonitor = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>();
        var configured = optionsMonitor.Get("configured");
        var code = optionsMonitor.Get("code");
        Assert.False(configured.SaveToken);
        Assert.True(configured.RequireHttpsMetadata);
        Assert.True(configured.RefreshOnIssuerKeyNotFound);
        Assert.Equal("bound-audience", configured.TokenValidationParameters.ValidAudience);
        Assert.True(code.SaveToken);
        Assert.False(code.RefreshOnIssuerKeyNotFound);
        Assert.False(code.RequireHttpsMetadata);
        var defaults = optionsMonitor.Get(Options.DefaultName);
        Assert.Null(defaults.TokenValidationParameters.ValidAudience);
        Assert.True(defaults.RequireHttpsMetadata);
        Assert.True(defaults.RefreshOnIssuerKeyNotFound);
    }

    [Fact]
    public void ForgotPasswordConfiguration_CanBeOverriddenInCode() {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            [$"{ForgotPasswordOptions.SectionName}:Method"] = "Link",
            [$"{ForgotPasswordOptions.SectionName}:FrontendResetUrl"] = "https://example.test/reset"
        }).Build();
        var services = new ServiceCollection();
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
            .AddForgotPassword(configuration, options => options.Method = ForgotPasswordMethod.VerificationCode);
        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<ForgotPasswordOptions>>().Value;
        Assert.Equal(ForgotPasswordMethod.VerificationCode, options.Method);
        Assert.Equal("https://example.test/reset", options.FrontendResetUrl);
    }

    [Fact]
    public void RefreshTokenConfiguration_CanBeOverriddenInCode() {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            [$"{RefreshTokenOptions.SectionName}:TokenLifetime"] = "10.00:00:00",
            [$"{RefreshTokenOptions.SectionName}:RevokeFamilyOnReuse"] = "false",
            [$"{RefreshTokenOptions.SectionName}:RefreshRequestsPerMinute"] = "41"
        }).Build();
        var services = new ServiceCollection();
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
            .AddRefreshToken(configuration, options => options.TokenLifetime = TimeSpan.FromDays(5));
        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<RefreshTokenOptions>>().Value;
        Assert.Equal(TimeSpan.FromDays(5), options.TokenLifetime);
        Assert.False(options.RevokeFamilyOnReuse);
        Assert.Equal(41, options.RefreshRequestsPerMinute);
    }

    [Fact]
    public async Task VerificationFeature_FailsStartupWithActionableMissingDependency() {
        var services = new ServiceCollection();
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
            .AddVerificationServices();
        using var provider = services.BuildServiceProvider();
        var validator = Assert.Single(provider.GetServices<IHostedService>(), service => service.GetType().Name.StartsWith("VerificationDependenciesStartupValidator", StringComparison.Ordinal));
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => validator.StartAsync(CancellationToken.None));
        Assert.Contains("IVerificationRequestStore", error.Message);
        Assert.Contains("AddVerificationRequestStore", error.Message);
    }

    [Fact]
    public void CoreRegistration_PreservesConsumerProvidedAccountService() {
        var services = new ServiceCollection();
        var consumerService = new Mock<IUserAccountService<IdentityUser>>().Object;
        services.AddSingleton(consumerService);
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();
        using var provider = services.BuildServiceProvider();
        Assert.Same(consumerService, provider.GetRequiredService<IUserAccountService<IdentityUser>>());
    }
}
