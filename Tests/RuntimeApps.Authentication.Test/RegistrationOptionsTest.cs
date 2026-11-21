using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.Features.Verification.Models;

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
    }

    [Fact]
    public void InvalidVerificationOptions_FailOptionsValidation() {
        var services = new ServiceCollection();
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
            .AddVerificationServices(options => options.CodeLength = 3);
        using var provider = services.BuildServiceProvider();
        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<VerificationOptions>>().Value);
    }
}
