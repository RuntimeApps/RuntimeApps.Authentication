using RuntimeApps.Authentication.Model;
using RuntimeApps.Authentication.Service;

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
        public void VerificationOptions_RejectsInvalidSecurityLimits() {
            var options = new VerificationOptions { MaximumFailedAttempts = 0 };

            Assert.Throws<InvalidOperationException>(() => options.Validate());
        }
    }
}