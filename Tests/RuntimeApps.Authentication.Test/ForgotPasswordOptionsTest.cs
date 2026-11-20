using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.Shared.Extensions;
using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
using RuntimeApps.Authentication.Features.PasswordRecovery.Models;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Features.Registration.Models;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Identity.Models;
using RuntimeApps.Authentication.Shared.Models;
using Xunit;

namespace RuntimeApps.Authentication.Test {
    public class ForgotPasswordOptionsTest {
        [Fact]
        public void Validate_DefaultOptions_UsesVerificationCode() {
            var options = new ForgotPasswordOptions();

            options.Validate();

            Assert.Equal(ForgotPasswordMethod.VerificationCode, options.Method);
        }

        [Fact]
        public void Validate_LinkModeRequiresHttpsFrontendUrl() {
            var options = new ForgotPasswordOptions {
                Method = ForgotPasswordMethod.Link,
                FrontendResetUrl = "http://frontend.example.com/reset-password"
            };

            Assert.Throws<InvalidOperationException>(() => options.Validate());
        }

        [Fact]
        public void Validate_LinkModeAcceptsHttpsFrontendUrl() {
            var options = new ForgotPasswordOptions {
                Method = ForgotPasswordMethod.Link,
                FrontendResetUrl = "https://frontend.example.com/reset-password"
            };

            options.Validate();
        }

        [Fact]
        public void Validate_LinkModeRejectsUrlWithCredentials() {
            var options = new ForgotPasswordOptions {
                Method = ForgotPasswordMethod.Link,
                FrontendResetUrl = "https://user:password@frontend.example.com/reset-password"
            };

            Assert.Throws<InvalidOperationException>(() => options.Validate());
        }

        [Fact]
        public void AddForgotPassword_RegistersIdentityPasswordResetTokenProvider() {
            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
                .AddVerificationServices()
                .AddForgotPassword();

            using var provider = services.BuildServiceProvider();
            var identityOptions = provider.GetRequiredService<IOptions<IdentityOptions>>().Value;

            Assert.True(identityOptions.Tokens.ProviderMap.ContainsKey(TokenOptions.DefaultProvider));
            Assert.True(provider.GetRequiredService<IServiceProviderIsService>()
                .IsService(typeof(DataProtectorTokenProvider<IdentityUser>)));
        }
    }
}