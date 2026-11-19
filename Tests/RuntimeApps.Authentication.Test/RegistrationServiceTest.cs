using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;
using RuntimeApps.Authentication.Service;

namespace RuntimeApps.Authentication.Test {
    public class RegistrationServiceTest {
        [Fact]
        public async Task Register_NewUser_CreatesPendingAccountAndStartsVerification() {
            var userManager = new Mock<IUserManager<IdentityUser>>();
            var workflow = new Mock<IVerificationWorkflowService<IdentityUser, string>>();
            var account = new Mock<IUserAccountService<IdentityUser>>();
            var user = new IdentityUser { Email = "new@example.com", UserName = "new@example.com" };
            var expiresAt = DateTimeOffset.UtcNow.AddMinutes(10);

            userManager.Setup(manager => manager.FindByEmailAsync(user.Email)).ReturnsAsync((IdentityUser)null);
            userManager.Setup(manager => manager.CreateAsync(user, "StrongPassword!1")).ReturnsAsync(IdentityResult.Success);
            workflow.Setup(service => service.StartAsync(
                    user, VerificationPurpose.Registration, VerificationChannel.Email, user.Email,
                    null, null, It.IsAny<CancellationToken>()))
                .ReturnsAsync(VerificationOperationResult.Success("opaque-handle", expiresAt));

            var service = CreateService(userManager, workflow, account);
            var result = await service.RegisterAsync(user, "StrongPassword!1");

            Assert.True(result.Succeeded);
            Assert.Equal("opaque-handle", result.Data.VerificationHandle);
            Assert.False(user.EmailConfirmed);
            userManager.Verify(manager => manager.CreateAsync(user, "StrongPassword!1"), Times.Once);
            account.Verify(manager => manager.CompleteRegistrationAsync(It.IsAny<IdentityUser>()), Times.Never);
        }

        [Fact]
        public async Task Register_ExistingPendingUser_ReusesAccountWithoutUpdatingIt() {
            var userManager = new Mock<IUserManager<IdentityUser>>();
            var workflow = new Mock<IVerificationWorkflowService<IdentityUser, string>>();
            var account = new Mock<IUserAccountService<IdentityUser>>();
            var existing = new IdentityUser { Email = "pending@example.com", UserName = "old-name" };
            var requested = new IdentityUser { Email = existing.Email, UserName = "new-name" };
            var expiresAt = DateTimeOffset.UtcNow.AddMinutes(10);

            userManager.Setup(manager => manager.FindByEmailAsync(existing.Email)).ReturnsAsync(existing);
            workflow.Setup(service => service.StartAsync(
                    existing, VerificationPurpose.Registration, VerificationChannel.Email, existing.Email,
                    null, null, It.IsAny<CancellationToken>()))
                .ReturnsAsync(VerificationOperationResult.Success("new-handle", expiresAt));

            var service = CreateService(userManager, workflow, account);
            var result = await service.RegisterAsync(requested, "AttackerSuppliedPassword!");

            Assert.True(result.Succeeded);
            userManager.Verify(manager => manager.CreateAsync(It.IsAny<IdentityUser>(), It.IsAny<string>()), Times.Never);
            Assert.Equal("old-name", existing.UserName);
            userManager.Verify(manager => manager.UpdateAsync(It.IsAny<IdentityUser>()), Times.Never);
        }

        [Fact]
        public async Task Register_ExistingConfirmedUser_ReturnsGenericResponseWithoutSending() {
            var userManager = new Mock<IUserManager<IdentityUser>>();
            var workflow = new Mock<IVerificationWorkflowService<IdentityUser, string>>();
            var account = new Mock<IUserAccountService<IdentityUser>>();
            var existing = new IdentityUser { Email = "confirmed@example.com", EmailConfirmed = true };
            userManager.Setup(manager => manager.FindByEmailAsync(existing.Email)).ReturnsAsync(existing);

            var service = CreateService(userManager, workflow, account);
            var result = await service.RegisterAsync(new IdentityUser { Email = existing.Email }, "Password!");

            Assert.True(result.Succeeded);
            Assert.False(string.IsNullOrWhiteSpace(result.Data.VerificationHandle));
            workflow.Verify(item => item.StartAsync(
                It.IsAny<IdentityUser>(), It.IsAny<VerificationPurpose>(), It.IsAny<VerificationChannel>(),
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        private static RegistrationService<IdentityUser, string> CreateService(
            Mock<IUserManager<IdentityUser>> userManager,
            Mock<IVerificationWorkflowService<IdentityUser, string>> workflow,
            Mock<IUserAccountService<IdentityUser>> account) =>
            new(userManager.Object, workflow.Object, account.Object,
                Options.Create(new VerificationOptions()));
    }
}