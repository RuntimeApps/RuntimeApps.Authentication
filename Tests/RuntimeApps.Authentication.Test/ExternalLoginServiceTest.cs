using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
using RuntimeApps.Authentication.Features.ExternalLogin.Services;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Test {
    /// <summary>Account resolution for validated external identities (<c>ResolveLoginAsync</c>).</summary>
    public class ExternalLoginServiceTest {
        private const string Provider = "Google";
        private const string Subject = "subject-1";
        private const string TrustedEmail = "person@example.com";

        private readonly Mock<IExternalLoginProvider<IdentityUser>> _provider = new();
        private readonly Mock<IUserManager<IdentityUser>> _userManager = new();
        private readonly Mock<IUserLoginManager<IdentityUser>> _loginManager = new();
        private readonly Mock<IUserEmailManager<IdentityUser>> _emailManager = new();
        private readonly Mock<IUserPasswordManager<IdentityUser>> _passwordManager = new();
        private readonly Mock<IExternalLoginEmailTrustPolicy<IdentityUser>> _trustPolicy = new();
        private readonly Mock<IRefreshTokenService<string>> _refreshTokens = new();
        private readonly UserLoginInfo _loginInfo = new(Provider, Subject, Provider);
        private bool _requireVerification;

        public ExternalLoginServiceTest() {
            _provider.SetupGet(p => p.Provider).Returns(Provider);
            _loginManager.Setup(m => m.FindByLoginAsync(Provider, Subject)).ReturnsAsync((IdentityUser)null);
            _emailManager.Setup(m => m.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync((IdentityUser)null);
            _userManager.Setup(m => m.CreateAsync(It.IsAny<IdentityUser>())).ReturnsAsync(IdentityResult.Success);
            _userManager.Setup(m => m.UpdateAsync(It.IsAny<IdentityUser>())).ReturnsAsync(IdentityResult.Success);
            _userManager.Setup(m => m.DeleteAsync(It.IsAny<IdentityUser>())).ReturnsAsync(IdentityResult.Success);
            _loginManager.Setup(m => m.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>())).ReturnsAsync(IdentityResult.Success);
            _passwordManager.Setup(m => m.RemovePasswordAsync(It.IsAny<IdentityUser>())).ReturnsAsync(IdentityResult.Success);
            _refreshTokens.Setup(s => s.RevokeAllAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(1);
        }

        private ExternalLoginService<IdentityUser, string> CreateService(bool withPasswordManager = true, bool withRefreshTokens = true) =>
            new(new[] { _provider.Object },
                _userManager.Object,
                _loginManager.Object,
                _emailManager.Object,
                withPasswordManager ? _passwordManager.Object : null,
                _trustPolicy.Object,
                Options.Create(new VerificationOptions { RequireEmailVerificationForExternalLogins = _requireVerification }),
                withRefreshTokens ? _refreshTokens.Object : null);

        private IdentityUser SetupProvider(string email, bool trusted, IdentityUser mapped = null) {
            var user = mapped ?? new IdentityUser { Email = email, UserName = email };
            _provider.Setup(p => p.ValidateAsync("token", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new ExternalLoginProviderResult<IdentityUser> {
                    User = user, LoginInfo = _loginInfo, Email = email, EmailVerified = trusted
                });
            _trustPolicy.Setup(p => p.IsEmailTrusted(Provider, It.IsAny<ExternalLoginProviderResult<IdentityUser>>())).Returns(trusted);
            return user;
        }

        private static void AssertGenericFailure(Result<IdentityUser> result) {
            Assert.False(result.Succeeded);
            Assert.Equal(ResultCode.BadRequest, result.Code);
            var error = Assert.Single(result.Errors);
            Assert.Equal("ExternalAuthenticationFailed", error.Code);
            Assert.Equal("External authentication could not be completed.", error.Description);
        }

        [Fact]
        public async Task UnknownProvider_FailsGenerically() {
            var result = await CreateService().ResolveLoginAsync("Nope", "token");

            AssertGenericFailure(result);
            _userManager.Verify(m => m.CreateAsync(It.IsAny<IdentityUser>()), Times.Never);
        }

        [Fact]
        public async Task ProviderRejectsToken_FailsGenerically() {
            _provider.Setup(p => p.ValidateAsync("token", It.IsAny<CancellationToken>()))
                .ReturnsAsync((ExternalLoginProviderResult<IdentityUser>)null);

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            AssertGenericFailure(result);
            _loginManager.Verify(m => m.FindByLoginAsync(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task ExistingLogin_ReturnsLinkedAccountWithoutWrites() {
            var linked = new IdentityUser { Id = "linked" };
            SetupProvider(TrustedEmail, trusted: true);
            _loginManager.Setup(m => m.FindByLoginAsync(Provider, Subject)).ReturnsAsync(linked);

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            Assert.True(result.Succeeded);
            Assert.Same(linked, result.Data);
            _emailManager.Verify(m => m.FindByEmailAsync(It.IsAny<string>()), Times.Never);
            _userManager.Verify(m => m.CreateAsync(It.IsAny<IdentityUser>()), Times.Never);
            _loginManager.Verify(m => m.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never);
        }

        [Fact]
        public async Task TrustedEmail_CreatesConfirmedAccountAndLinksLogin() {
            var user = SetupProvider(TrustedEmail, trusted: true);

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            Assert.True(result.Succeeded);
            Assert.Same(user, result.Data);
            Assert.True(user.EmailConfirmed);
            Assert.Equal(TrustedEmail, user.Email);
            Assert.Equal(TrustedEmail, user.UserName);
            _userManager.Verify(m => m.CreateAsync(user), Times.Once);
            _loginManager.Verify(m => m.AddLoginAsync(user, _loginInfo), Times.Once);
        }

        [Fact]
        public async Task TrustedEmail_MapperLeftEmailBlank_UsesTrustedEmail() {
            var user = SetupProvider(TrustedEmail, trusted: true, mapped: new IdentityUser());

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            Assert.True(result.Succeeded);
            Assert.Equal(TrustedEmail, user.Email);
            Assert.Equal(TrustedEmail, user.UserName);
            Assert.True(user.EmailConfirmed);
        }

        [Fact]
        public async Task TrustedEmail_ConfirmedExistingAccount_LinksWithoutTouchingPassword() {
            SetupProvider(TrustedEmail, trusted: true);
            var existing = new IdentityUser { Id = "existing", Email = TrustedEmail, EmailConfirmed = true };
            _emailManager.Setup(m => m.FindByEmailAsync(TrustedEmail)).ReturnsAsync(existing);

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            Assert.True(result.Succeeded);
            Assert.Same(existing, result.Data);
            _loginManager.Verify(m => m.AddLoginAsync(existing, _loginInfo), Times.Once);
            _passwordManager.Verify(m => m.RemovePasswordAsync(It.IsAny<IdentityUser>()), Times.Never);
            _refreshTokens.Verify(s => s.RevokeAllAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            _userManager.Verify(m => m.CreateAsync(It.IsAny<IdentityUser>()), Times.Never);
        }

        [Fact]
        public async Task TrustedEmail_UnconfirmedExistingAccount_IsNeutralizedBeforeLinking() {
            SetupProvider(TrustedEmail, trusted: true);
            var existing = new IdentityUser { Id = "existing", Email = TrustedEmail, EmailConfirmed = false };
            _emailManager.Setup(m => m.FindByEmailAsync(TrustedEmail)).ReturnsAsync(existing);
            var order = new List<string>();
            _passwordManager.Setup(m => m.RemovePasswordAsync(existing)).Returns(() => {
                order.Add("remove-password");
                return Task.FromResult(IdentityResult.Success);
            });
            _refreshTokens.Setup(s => s.RevokeAllAsync("existing", It.IsAny<CancellationToken>())).Returns(() => {
                order.Add("revoke-sessions");
                return Task.FromResult(1);
            });
            _loginManager.Setup(m => m.AddLoginAsync(existing, _loginInfo)).Returns(() => {
                order.Add("add-login");
                return Task.FromResult(IdentityResult.Success);
            });
            _userManager.Setup(m => m.UpdateAsync(existing)).Returns(() => {
                order.Add("confirm-email");
                return Task.FromResult(IdentityResult.Success);
            });

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            Assert.True(result.Succeeded);
            Assert.Same(existing, result.Data);
            Assert.True(existing.EmailConfirmed);
            Assert.Equal(new[] { "remove-password", "revoke-sessions", "add-login", "confirm-email" }, order);
            _userManager.Verify(m => m.CreateAsync(It.IsAny<IdentityUser>()), Times.Never);
        }

        [Fact]
        public async Task UnconfirmedExistingAccount_WithoutPasswordManager_FailsClosedWithoutLinking() {
            SetupProvider(TrustedEmail, trusted: true);
            var existing = new IdentityUser { Id = "existing", Email = TrustedEmail, EmailConfirmed = false };
            _emailManager.Setup(m => m.FindByEmailAsync(TrustedEmail)).ReturnsAsync(existing);

            var result = await CreateService(withPasswordManager: false).ResolveLoginAsync(Provider, "token");

            AssertGenericFailure(result);
            _loginManager.Verify(m => m.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never);
            Assert.False(existing.EmailConfirmed);
        }

        [Fact]
        public async Task UnconfirmedExistingAccount_PasswordRemovalFails_DoesNotLink() {
            SetupProvider(TrustedEmail, trusted: true);
            var existing = new IdentityUser { Id = "existing", Email = TrustedEmail, EmailConfirmed = false };
            _emailManager.Setup(m => m.FindByEmailAsync(TrustedEmail)).ReturnsAsync(existing);
            _passwordManager.Setup(m => m.RemovePasswordAsync(existing)).ReturnsAsync(IdentityResult.Failed());

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            AssertGenericFailure(result);
            _loginManager.Verify(m => m.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never);
            Assert.False(existing.EmailConfirmed);
        }

        [Fact]
        public async Task UnconfirmedExistingAccount_LinkFails_StaysUnconfirmed() {
            SetupProvider(TrustedEmail, trusted: true);
            var existing = new IdentityUser { Id = "existing", Email = TrustedEmail, EmailConfirmed = false };
            _emailManager.Setup(m => m.FindByEmailAsync(TrustedEmail)).ReturnsAsync(existing);
            _loginManager.Setup(m => m.AddLoginAsync(existing, _loginInfo)).ReturnsAsync(IdentityResult.Failed());

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            AssertGenericFailure(result);
            Assert.False(existing.EmailConfirmed);
            _userManager.Verify(m => m.UpdateAsync(It.IsAny<IdentityUser>()), Times.Never);
            _userManager.Verify(m => m.DeleteAsync(It.IsAny<IdentityUser>()), Times.Never);
        }

        [Fact]
        public async Task UnconfirmedExistingAccount_ConfirmUpdateFails_ResetsFlagAndFails() {
            SetupProvider(TrustedEmail, trusted: true);
            var existing = new IdentityUser { Id = "existing", Email = TrustedEmail, EmailConfirmed = false };
            _emailManager.Setup(m => m.FindByEmailAsync(TrustedEmail)).ReturnsAsync(existing);
            _userManager.Setup(m => m.UpdateAsync(existing)).ReturnsAsync(IdentityResult.Failed());

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            AssertGenericFailure(result);
            Assert.False(existing.EmailConfirmed);
        }

        [Fact]
        public async Task UntrustedEmail_IsIgnoredForLookupAndNotStored() {
            var user = SetupProvider("victim@example.com", trusted: false);

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            Assert.True(result.Succeeded);
            Assert.Same(user, result.Data);
            _emailManager.Verify(m => m.FindByEmailAsync(It.IsAny<string>()), Times.Never);
            Assert.Null(user.Email);
            Assert.False(user.EmailConfirmed);
            Assert.Equal("Google_subject-1", user.UserName);
        }

        [Fact]
        public async Task UntrustedEmail_ExistingAccountWithSameEmail_IsNeverLinked() {
            SetupProvider("victim@example.com", trusted: false);
            var victim = new IdentityUser { Id = "victim", Email = "victim@example.com", EmailConfirmed = true };
            _emailManager.Setup(m => m.FindByEmailAsync("victim@example.com")).ReturnsAsync(victim);

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            Assert.True(result.Succeeded);
            Assert.NotSame(victim, result.Data);
            _loginManager.Verify(m => m.AddLoginAsync(victim, It.IsAny<UserLoginInfo>()), Times.Never);
        }

        [Fact]
        public async Task UntrustedEmail_KeepsMapperUserNameThatIsNotTheEmail() {
            var user = SetupProvider("someone@example.com", trusted: false,
                mapped: new IdentityUser { Email = "someone@example.com", UserName = "custom-name" });

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            Assert.True(result.Succeeded);
            Assert.Equal("custom-name", user.UserName);
            Assert.Null(user.Email);
        }

        [Fact]
        public async Task NoEmailAtAll_UsesProviderSubjectUserName() {
            var user = SetupProvider(null, trusted: true, mapped: new IdentityUser());

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            Assert.True(result.Succeeded);
            Assert.Equal("Google_subject-1", user.UserName);
            Assert.False(user.EmailConfirmed);
        }

        [Fact]
        public async Task RequireVerification_UntrustedEmail_FailsBeforeAnyWrite() {
            _requireVerification = true;
            SetupProvider("person@example.com", trusted: false);

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            AssertGenericFailure(result);
            _emailManager.Verify(m => m.FindByEmailAsync(It.IsAny<string>()), Times.Never);
            _userManager.Verify(m => m.CreateAsync(It.IsAny<IdentityUser>()), Times.Never);
        }

        [Fact]
        public async Task CreateFails_FailsGenericallyWithoutLinkingOrDeleting() {
            SetupProvider(TrustedEmail, trusted: true);
            _userManager.Setup(m => m.CreateAsync(It.IsAny<IdentityUser>())).ReturnsAsync(IdentityResult.Failed());

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            AssertGenericFailure(result);
            _loginManager.Verify(m => m.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never);
            _userManager.Verify(m => m.DeleteAsync(It.IsAny<IdentityUser>()), Times.Never);
        }

        [Fact]
        public async Task LinkFailsAfterCreate_DeletesCreatedAccount() {
            var user = SetupProvider(TrustedEmail, trusted: true);
            _loginManager.Setup(m => m.AddLoginAsync(user, _loginInfo)).ReturnsAsync(IdentityResult.Failed());

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            AssertGenericFailure(result);
            _userManager.Verify(m => m.DeleteAsync(user), Times.Once);
        }

        [Fact]
        public async Task LinkFailsAndCompensatingDeleteThrows_StillReturnsGenericFailure() {
            var user = SetupProvider(TrustedEmail, trusted: true);
            _loginManager.Setup(m => m.AddLoginAsync(user, _loginInfo)).ReturnsAsync(IdentityResult.Failed());
            _userManager.Setup(m => m.DeleteAsync(user)).ThrowsAsync(new InvalidOperationException("db detail"));

            var result = await CreateService().ResolveLoginAsync(Provider, "token");

            AssertGenericFailure(result);
            Assert.DoesNotContain("db detail", result.Errors.Single().Description);
        }

        [Fact]
        public async Task CancelledBeforeStart_Throws_AndWritesNothing() {
            SetupProvider(TrustedEmail, trusted: true);
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                CreateService().ResolveLoginAsync(Provider, "token", cancellation.Token));

            _userManager.Verify(m => m.CreateAsync(It.IsAny<IdentityUser>()), Times.Never);
        }

        [Fact]
        public async Task CancellationDuringCreate_DoesNotInterruptLinking() {
            var user = SetupProvider(TrustedEmail, trusted: true);
            using var cancellation = new CancellationTokenSource();
            _userManager.Setup(m => m.CreateAsync(user)).Returns(() => {
                cancellation.Cancel();
                return Task.FromResult(IdentityResult.Success);
            });

            var result = await CreateService().ResolveLoginAsync(Provider, "token", cancellation.Token);

            Assert.True(result.Succeeded);
            _loginManager.Verify(m => m.AddLoginAsync(user, _loginInfo), Times.Once);
            _userManager.Verify(m => m.DeleteAsync(It.IsAny<IdentityUser>()), Times.Never);
        }
    }
}
