using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;
using RuntimeApps.Authentication.Service;
using Xunit;

namespace RuntimeApps.Authentication.Test {
    public class ForgotPasswordServiceTest {
        [Fact]
        public async Task Request_UnknownEmail_ReturnsGenericResponseWithNonexistentHandle() {
            var userManager = new Mock<IUserManager<IdentityUser>>();
            var workflow = new Mock<IForgotPasswordVerificationWorkflow<IdentityUser, string>>();
            userManager.Setup(manager => manager.FindByEmailAsync("missing@example.com"))
                .ReturnsAsync((IdentityUser)null);

            var service = CreateService(userManager, workflow);
            var response = await service.RequestAsync("missing@example.com");

            Assert.False(string.IsNullOrWhiteSpace(response.VerificationHandle));
            Assert.Equal(43, response.VerificationHandle.Length);
            workflow.Verify(workflow => workflow.StartAsync(
                It.IsAny<IdentityUser>(), It.IsAny<VerificationPurpose>(), It.IsAny<VerificationChannel>(),
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Request_ConfirmedEmail_ReturnsStartedVerificationHandle() {
            var userManager = new Mock<IUserManager<IdentityUser>>();
            var workflow = new Mock<IForgotPasswordVerificationWorkflow<IdentityUser, string>>();
            var user = new IdentityUser {
                Email = "person@example.com",
                EmailConfirmed = true
            };
            userManager.Setup(manager => manager.FindByEmailAsync(user.Email)).ReturnsAsync(user);
            workflow.Setup(service => service.StartAsync(
                    user, VerificationPurpose.PasswordReset, VerificationChannel.Email, user.Email,
                    null, null, It.IsAny<CancellationToken>()))
                .ReturnsAsync(VerificationOperationResult.Success("real-handle", DateTimeOffset.UtcNow.AddMinutes(10)));

            var service = CreateService(userManager, workflow);
            var response = await service.RequestAsync(user.Email);

            Assert.Equal("real-handle", response.VerificationHandle);
            workflow.Verify(service => service.StartAsync(
                user, VerificationPurpose.PasswordReset, VerificationChannel.Email, user.Email,
                null, null, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Request_UnconfirmedEmail_DoesNotStartVerification() {
            var userManager = new Mock<IUserManager<IdentityUser>>();
            var workflow = new Mock<IForgotPasswordVerificationWorkflow<IdentityUser, string>>();
            var user = new IdentityUser {
                Email = "unconfirmed@example.com",
                EmailConfirmed = false
            };
            userManager.Setup(manager => manager.FindByEmailAsync(user.Email)).ReturnsAsync(user);

            var service = CreateService(userManager, workflow);
            var response = await service.RequestAsync(user.Email);

            Assert.False(string.IsNullOrWhiteSpace(response.VerificationHandle));
            workflow.Verify(service => service.StartAsync(
                It.IsAny<IdentityUser>(), It.IsAny<VerificationPurpose>(), It.IsAny<VerificationChannel>(),
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Request_ConfirmedEmailInLinkMode_DoesNotReturnVerificationHandle() {
            var userManager = new Mock<IUserManager<IdentityUser>>();
            var workflow = new Mock<IForgotPasswordVerificationWorkflow<IdentityUser, string>>();
            var user = new IdentityUser {
                Email = "person@example.com",
                EmailConfirmed = true
            };
            userManager.Setup(manager => manager.FindByEmailAsync(user.Email)).ReturnsAsync(user);
            workflow.Setup(service => service.StartAsync(
                    user, VerificationPurpose.PasswordReset, VerificationChannel.Email, user.Email,
                    null, null, It.IsAny<CancellationToken>()))
                .ReturnsAsync(VerificationOperationResult.Success("real-handle", DateTimeOffset.UtcNow.AddMinutes(10)));

            var service = CreateService(userManager, workflow, ForgotPasswordMethod.Link);
            var response = await service.RequestAsync(user.Email);

            Assert.Null(response.VerificationHandle);
            workflow.Verify(service => service.StartAsync(
                user, VerificationPurpose.PasswordReset, VerificationChannel.Email, user.Email,
                null, null, It.IsAny<CancellationToken>()), Times.Once);
        }

        private static ForgotPasswordService<IdentityUser, string> CreateService(
            Mock<IUserManager<IdentityUser>> userManager,
            Mock<IForgotPasswordVerificationWorkflow<IdentityUser, string>> workflow,
            ForgotPasswordMethod method = ForgotPasswordMethod.VerificationCode) {
            var store = new Mock<IUserStore<IdentityUser>>();
            var identityManager = new UserManager<IdentityUser>(
                store.Object,
                Options.Create(new IdentityOptions()),
                new PasswordHasher<IdentityUser>(),
                Array.Empty<IUserValidator<IdentityUser>>(),
                Array.Empty<IPasswordValidator<IdentityUser>>(),
                new UpperInvariantLookupNormalizer(),
                new IdentityErrorDescriber(),
                new ServiceCollection().BuildServiceProvider(),
                NullLogger<UserManager<IdentityUser>>.Instance);

            return new ForgotPasswordService<IdentityUser, string>(
                userManager.Object,
                identityManager,
                workflow.Object,
                Array.Empty<IPasswordValidator<IdentityUser>>(),
                new ServiceCollection().BuildServiceProvider(),
                NullLogger<ForgotPasswordService<IdentityUser, string>>.Instance,
                Options.Create(new ForgotPasswordOptions {
                    Method = method,
                    FrontendResetUrl = method == ForgotPasswordMethod.Link
                        ? "https://frontend.example.com/reset-password"
                        : null
                }));
        }
    }
}