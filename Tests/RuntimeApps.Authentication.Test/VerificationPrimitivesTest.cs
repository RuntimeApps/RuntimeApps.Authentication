using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
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
    public class VerificationPrimitivesTest {
        [Fact]
        public void VerificationHandle_Create_ReturnsIndependentOpaqueValues() {
            var first = VerificationHandle.Create();
            var second = VerificationHandle.Create();

            Assert.NotEqual(first, second);
            Assert.Equal(64, VerificationHandle.ComputeHash(first).Length);
            Assert.NotEqual(VerificationHandle.ComputeHash(first), VerificationHandle.ComputeHash(second));
        }

        [Fact]
        public async Task RandomVerificationCodeGenerator_GeneratesConfiguredNumericCode() {
            var generator = new RandomVerificationCodeGenerator<object, string>();
            var options = new VerificationOptions { CodeLength = 6 };
            var context = new VerificationCodeContext<object, string> {
                UserId = "user-1",
                RequestId = "request-1",
                Purpose = VerificationPurpose.Registration,
                Channel = VerificationChannel.Email,
                Destination = "person@example.com"
            };

            var code = await generator.GenerateAsync(context, options);

            Assert.Equal(6, code.Length);
            Assert.All(code, character => Assert.InRange(character, '0', '9'));
        }

        [Fact]
        public void DataProtectionVerifier_BindsCodeToRequestAndDestination() {
            var services = new ServiceCollection();
            services.AddDataProtection().UseEphemeralDataProtectionProvider();
            using var provider = services.BuildServiceProvider();
            var verifier = new DataProtectionVerificationCodeVerifier<string>(
                provider.GetRequiredService<IDataProtectionProvider>());
            var request = new VerificationRequest<string> {
                Id = "request-1",
                UserId = "user-1",
                Purpose = VerificationPurpose.Registration,
                Channel = VerificationChannel.Email,
                NormalizedDestination = "PERSON@EXAMPLE.COM"
            };
            request.CodeVerifier = verifier.CreateVerifier("123456", request);

            Assert.True(verifier.Verify("123456", request));
            Assert.False(verifier.Verify("123457", request));

            request.NormalizedDestination = "OTHER@EXAMPLE.COM";
            Assert.False(verifier.Verify("123456", request));
        }

        [Fact]
        public void VerificationOptions_RejectsInvalidSecurityLimits() {
            var options = new VerificationOptions { MaximumFailedAttempts = 0 };

            Assert.Throws<InvalidOperationException>(() => options.Validate());
        }
    }
}
