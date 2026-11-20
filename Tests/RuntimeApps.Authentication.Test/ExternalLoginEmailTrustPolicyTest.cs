using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
using RuntimeApps.Authentication.Features.PasswordRecovery.Models;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Features.Registration.Models;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Identity.Models;
using RuntimeApps.Authentication.Shared.Models;
using RuntimeApps.Authentication.Features.Account.Services;
using RuntimeApps.Authentication.Features.ExternalLogin.Providers;
using RuntimeApps.Authentication.Features.ExternalLogin.Services;
using RuntimeApps.Authentication.Features.PasswordRecovery.Services;
using RuntimeApps.Authentication.Features.RefreshTokens.Services;
using RuntimeApps.Authentication.Features.Registration.Services;
using RuntimeApps.Authentication.Features.Verification.Services;
using RuntimeApps.Authentication.Identity;
namespace RuntimeApps.Authentication.Test {
    public class ExternalLoginEmailTrustPolicyTest {
        private readonly DefaultExternalLoginEmailTrustPolicy<object> _policy = new();

        [Theory]
        [InlineData("person@gmail.com", null, true)]
        [InlineData("person@company.com", "company.com", true)]
        [InlineData("person@company.com", "other.com", false)]
        [InlineData("person@example.com", null, false)]
        public void GoogleEmailTrust_RequiresVerifiedEmailAndTrustedDomain(
            string email, string hostedDomain, bool expected) {
            var result = new ExternalLoginProviderResult<object> {
                User = new object(),
                Email = email,
                EmailVerified = true,
                HostedDomain = hostedDomain
            };

            Assert.Equal(expected, _policy.IsEmailTrusted("GOOGLE", result));
        }

        [Fact]
        public void FacebookEmail_IsNeverTrustedByDefault() {
            var result = new ExternalLoginProviderResult<object> {
                User = new object(),
                Email = "person@example.com",
                EmailVerified = true
            };

            Assert.False(_policy.IsEmailTrusted("FACEBOOK", result));
        }

        [Fact]
        public void UnverifiedGoogleEmail_IsNotTrusted() {
            var result = new ExternalLoginProviderResult<object> {
                User = new object(),
                Email = "person@gmail.com",
                EmailVerified = false
            };

            Assert.False(_policy.IsEmailTrusted("GOOGLE", result));
        }
    }
}