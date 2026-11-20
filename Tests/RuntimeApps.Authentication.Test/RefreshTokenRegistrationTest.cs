using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.Shared.Extensions;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.PasswordRecovery.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.Registration.Contracts;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;
namespace RuntimeApps.Authentication.Test {
    public class RefreshTokenRegistrationTest {
        [Fact]
        public void RefreshTokenServices_AreNotRegisteredByDefault() {
            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();

            using var provider = services.BuildServiceProvider();
            var serviceAvailability = provider.GetRequiredService<IServiceProviderIsService>();

            Assert.False(serviceAvailability.IsService(typeof(IRefreshTokenService<string>)));
            Assert.False(serviceAvailability.IsService(typeof(IRefreshTokenStore<string>)));
        }
    }
}