using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using RuntimeApps.Authentication.Extensions;
using RuntimeApps.Authentication.Interface;

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