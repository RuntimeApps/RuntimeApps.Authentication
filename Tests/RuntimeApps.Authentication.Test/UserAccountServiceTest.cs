using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Moq;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.PasswordRecovery.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.Registration.Contracts;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Features.Account.Services;
using RuntimeApps.Authentication.Features.ExternalLogin.Providers;
using RuntimeApps.Authentication.Features.ExternalLogin.Services;
using RuntimeApps.Authentication.Features.PasswordRecovery.Services;
using RuntimeApps.Authentication.Features.RefreshTokens.Services;
using RuntimeApps.Authentication.Features.Registration.Services;
using RuntimeApps.Authentication.Features.Verification.Services;
using RuntimeApps.Authentication.Identity;
namespace RuntimeApps.Authentication.Test {
    public class UserAccountServiceTest {
        private const IdentityUser nullUSer = null;
        private readonly Mock<IUserManager<IdentityUser>> _userManagerMock;
                    private readonly Mock<IUserLoginManager<IdentityUser>> _loginManagerMock;
                    private readonly Mock<IUserEmailManager<IdentityUser>> _emailManagerMock;
        private readonly Mock<ISignInManager<IdentityUser>> _signInManagerMock;
        private readonly Mock<IAuthenticationSessionIssuer<IdentityUser>> _sessionIssuerMock;
        private readonly Mock<IExternalLoginProvider<IdentityUser>> _externalLoginProvider1;
        private readonly Mock<IExternalLoginProvider<IdentityUser>> _externalLoginProvider2;
        private readonly Mock<IExternalLoginEmailTrustPolicy<IdentityUser>> _externalLoginEmailTrustPolicyMock;
        private readonly Mock<IAuthenticationHandlerProvider> _authenticationHandlerProviderMock;
        private readonly Mock<IHttpContextAccessor> _httpContextAccessorMock;
        private readonly Mock<IUserClaimsPrincipalFactory<IdentityUser>> _userClaimsPrincipalFactoryMock;
        private readonly Mock<IAuthenticationSchemeProvider> _authenticationSchemeProviderMock;
        private readonly IUserAccountService<IdentityUser> _userAccountService;

        public UserAccountServiceTest() {
            _userManagerMock = new Mock<IUserManager<IdentityUser>>();
                        _loginManagerMock = new Mock<IUserLoginManager<IdentityUser>>();
                        _emailManagerMock = new Mock<IUserEmailManager<IdentityUser>>();
            _signInManagerMock = new Mock<ISignInManager<IdentityUser>>();
            _sessionIssuerMock = new Mock<IAuthenticationSessionIssuer<IdentityUser>>();
            _externalLoginProvider1 = new Mock<IExternalLoginProvider<IdentityUser>>();
            _externalLoginProvider2 = new Mock<IExternalLoginProvider<IdentityUser>>();
            _externalLoginEmailTrustPolicyMock = new Mock<IExternalLoginEmailTrustPolicy<IdentityUser>>();
            _authenticationHandlerProviderMock= new Mock<IAuthenticationHandlerProvider>();
            _httpContextAccessorMock= new Mock<IHttpContextAccessor>();
            _userClaimsPrincipalFactoryMock = new Mock<IUserClaimsPrincipalFactory<IdentityUser>>();
            _authenticationSchemeProviderMock = new Mock<IAuthenticationSchemeProvider>();
            _userAccountService = new UserAccountService<IdentityUser, string>(_userManagerMock.Object, _signInManagerMock.Object, new IExternalLoginProvider<IdentityUser>[] {
                _externalLoginProvider1.Object,
                _externalLoginProvider2.Object
            },
            _authenticationHandlerProviderMock.Object,
            _httpContextAccessorMock.Object,
            _userClaimsPrincipalFactoryMock.Object,
            _authenticationSchemeProviderMock.Object,
            null, null, null, _externalLoginEmailTrustPolicyMock.Object, null, null, _loginManagerMock.Object, _emailManagerMock.Object, _sessionIssuerMock.Object);

            _authenticationSchemeProviderMock.Setup(p => p.GetDefaultSignInSchemeAsync())
                .ReturnsAsync((AuthenticationScheme)null);
        }

        [Fact]
        public async Task Login_Success() {
            //Arrange
            string userName = "userName", password = "password";
            var user = new IdentityUser() {
                Id = "userId",
                UserName = userName,
                EmailConfirmed = true
            };
            var token = new RuntimeApps.Authentication.Shared.Models.Token() {
                AuthenticationToken = "",
                ExpireDate = DateTimeOffset.Now.AddDays(30),
            };
            _userManagerMock.Setup(u => u.FindByNameAsync(userName))
                .ReturnsAsync(user);
            _signInManagerMock.Setup(S => S.PasswordSignInAsync(user, password, It.IsAny<bool>(), It.IsAny<bool>()))
                .ReturnsAsync(SignInResult.Success);
            _sessionIssuerMock.Setup(t => t.IssueAsync(user, It.IsAny<CancellationToken>()))
                .ReturnsAsync(token);

            //Act
            var result = await _userAccountService.LoginAsync(userName, password);

            //Assert
            result.Succeeded.Should().BeTrue();
            result.Data.Should().NotBeNull()
                .And.Be(user);
            result.Meta.Should().NotBeNull()
                .And.Be(token);
        }

        [Fact]
        public async Task Login_UnconfirmedEmail_IsRejectedBeforePasswordCheck() {
            const string userName = "pending-user";
            var user = new IdentityUser { UserName = userName, Email = "pending@example.com", EmailConfirmed = false };
            _userManagerMock.Setup(manager => manager.FindByNameAsync(userName)).ReturnsAsync(user);

            var result = await _userAccountService.LoginAsync(userName, "password");

            Assert.False(result.Succeeded);
            _signInManagerMock.Verify(manager => manager.PasswordSignInAsync(
                It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>()), Times.Never());
        }

        [Fact]
        public async Task Login_WrongUserName() {
            //Arrange
            string userName = "userName", password = "password";
            _userManagerMock.Setup(u => u.FindByNameAsync(It.IsAny<string>()))
                .ReturnsAsync(nullUSer);

            //Act
            var result = await _userAccountService.LoginAsync(userName, password);

            //Assert
            result.Succeeded.Should().BeFalse();
            result.Data.Should().BeNull();
            result.Meta.Should().BeNull();
        }

        [Fact]
        public async Task Login_WrongPassword() {
            //Arrange
            string userName = "userName", password = "password";
            var user = new IdentityUser() {
                Id = "userId",
                UserName = userName,
            };
            _userManagerMock.Setup(u => u.FindByNameAsync(It.IsAny<string>()))
                .ReturnsAsync(nullUSer);
            _signInManagerMock.Setup(S => S.PasswordSignInAsync(user, password, It.IsAny<bool>(), It.IsAny<bool>()))
                .ReturnsAsync(SignInResult.Failed);

            //Act
            var result = await _userAccountService.LoginAsync(userName, password);

            //Assert
            result.Succeeded.Should().BeFalse();
            result.Data.Should().BeNull();
            result.Meta.Should().BeNull();
        }

        [Fact]
        public async Task Login_TwoFactorRequired_ReturnsContinuationWithoutIssuingSession() {
            var user = new IdentityUser { UserName = "mfa-user", EmailConfirmed = true };
            _userManagerMock.Setup(manager => manager.FindByNameAsync(user.UserName)).ReturnsAsync(user);
            _signInManagerMock.Setup(manager => manager.PasswordSignInAsync(user, "password", false, true))
                .ReturnsAsync(SignInResult.TwoFactorRequired);

            var result = await _userAccountService.LoginAsync(user.UserName, "password");

            Assert.False(result.Succeeded);
            Assert.Equal(RuntimeApps.Authentication.Shared.Models.ResultCode.Accepted, result.Code);
            Assert.Null(result.Data);
            Assert.Null(result.Meta);
            _sessionIssuerMock.Verify(issuer => issuer.IssueAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Theory]
        [InlineData(true, RuntimeApps.Authentication.Shared.Models.ResultCode.BadRequest)]
        [InlineData(false, RuntimeApps.Authentication.Shared.Models.ResultCode.BadRequest)]
        public async Task Login_LockedOutOrNotAllowed_DoesNotIssueSession(bool lockedOut, RuntimeApps.Authentication.Shared.Models.ResultCode expectedCode) {
            var user = new IdentityUser { UserName = "restricted", EmailConfirmed = true };
            _userManagerMock.Setup(manager => manager.FindByNameAsync(user.UserName)).ReturnsAsync(user);
            _signInManagerMock.Setup(manager => manager.PasswordSignInAsync(user, "password", false, true))
                .ReturnsAsync(lockedOut ? SignInResult.LockedOut : SignInResult.NotAllowed);

            var result = await _userAccountService.LoginAsync(user.UserName, "password");

            Assert.False(result.Succeeded);
            Assert.Equal(expectedCode, result.Code);
            _sessionIssuerMock.Verify(issuer => issuer.IssueAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task CompleteRegistration_Success_ConfirmedUser() {
            var user = new IdentityUser { Email = "test@test.com", EmailConfirmed = true };
            var token = new RuntimeApps.Authentication.Shared.Models.Token {
                AuthenticationToken = "",
                ExpireDate = DateTimeOffset.Now.AddDays(30),
            };
            _sessionIssuerMock.Setup(provider => provider.IssueAsync(user, It.IsAny<CancellationToken>())).ReturnsAsync(token);

            var result = await _userAccountService.CompleteRegistrationAsync(user);

            result.Succeeded.Should().BeTrue();
            result.Data.Should().Be(user);
            result.Meta.Should().Be(token);
        }

        [Fact]
        public async Task CompleteRegistration_UnconfirmedUser_IsRejected() {
            var user = new IdentityUser { Email = "test@test.com", EmailConfirmed = false };

            var result = await _userAccountService.CompleteRegistrationAsync(user);

            result.Succeeded.Should().BeFalse();
            result.Code.Should().Be(RuntimeApps.Authentication.Shared.Models.ResultCode.Forbidden);
            _sessionIssuerMock.Verify(provider => provider.IssueAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task CompleteRegistration_WithoutIssuer_FailsExplicitly() {
            var service = new UserAccountService<IdentityUser, string>(
                _userManagerMock.Object, _signInManagerMock.Object, Array.Empty<IExternalLoginProvider<IdentityUser>>(),
                _authenticationHandlerProviderMock.Object, _httpContextAccessorMock.Object,
                _userClaimsPrincipalFactoryMock.Object, _authenticationSchemeProviderMock.Object,
                null, null, null, _externalLoginEmailTrustPolicyMock.Object, null, null,
                _loginManagerMock.Object, _emailManagerMock.Object, null);

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                service.CompleteRegistrationAsync(new IdentityUser { EmailConfirmed = true }));
        }

        [Fact]
        public async Task ExternalLogin_Success_CreateNewUser() {
            //Arrange
            string provider = "Google", token = "token";
            var user = new IdentityUser() {
                Email = "test@test.com"
            };
            var appToken = new RuntimeApps.Authentication.Shared.Models.Token() {
                AuthenticationToken = "",
                ExpireDate = DateTimeOffset.Now.AddDays(30),
            };
            var loginInfo = new UserLoginInfo(provider, token, provider);
            _externalLoginProvider1.SetupGet(e => e.Provider)
                .Returns("Not Selected Provided");
            _externalLoginProvider2.SetupGet(e => e.Provider)
                .Returns(provider);
            _externalLoginProvider2.Setup(e => e.ValidateAsync(token))
                .ReturnsAsync(new RuntimeApps.Authentication.Features.ExternalLogin.Models.ExternalLoginProviderResult<IdentityUser> {
                    User = user, LoginInfo = loginInfo, Email = user.Email, EmailVerified = false
                });
            _externalLoginEmailTrustPolicyMock.Setup(policy => policy.IsEmailTrusted(provider, It.IsAny<RuntimeApps.Authentication.Features.ExternalLogin.Models.ExternalLoginProviderResult<IdentityUser>>())).Returns(true);
            _loginManagerMock.Setup(u => u.FindByLoginAsync(provider, token))
                .ReturnsAsync(nullUSer);
            _emailManagerMock.Setup(u => u.FindByEmailAsync(user.Email))
                .ReturnsAsync(nullUSer);
            _userManagerMock.Setup(u => u.CreateAsync(user))
                .ReturnsAsync(IdentityResult.Success);
            _loginManagerMock.Setup(u => u.AddLoginAsync(user, loginInfo))
                .ReturnsAsync(IdentityResult.Success);
            _sessionIssuerMock.Setup(t => t.IssueAsync(user, It.IsAny<CancellationToken>()))
                .ReturnsAsync(appToken);

            //Act
            var result = await _userAccountService.ExternalLoginAsync(provider, token);

            //Assert
            result.Succeeded.Should().BeTrue();
            result.Data.Should().NotBeNull()
                .And.Be(user);
            result.Meta.Should().NotBeNull()
                .And.Be(appToken);
            _userManagerMock.Verify(u => u.CreateAsync(It.IsAny<IdentityUser>()), Times.Once());
            _loginManagerMock.Verify(u => u.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Once());
        }

        [Fact]
        public async Task ExternalLogin_ExistingEmail_DoesNotAutomaticallyLink() {
            const string provider = "Google";
            const string token = "provider-token";
            var existingUser = new IdentityUser { Email = "existing@example.com", EmailConfirmed = true };
            var loginInfo = new UserLoginInfo(provider, token, provider);
            _externalLoginProvider1.SetupGet(item => item.Provider).Returns("Not Selected");
            _externalLoginProvider2.SetupGet(item => item.Provider).Returns(provider);
            _externalLoginProvider2.Setup(item => item.ValidateAsync(token))
                .ReturnsAsync(new RuntimeApps.Authentication.Features.ExternalLogin.Models.ExternalLoginProviderResult<IdentityUser> {
                    User = new IdentityUser { Email = existingUser.Email },
                    LoginInfo = loginInfo,
                    Email = existingUser.Email,
                    EmailVerified = true
                });
            _loginManagerMock.Setup(manager => manager.FindByLoginAsync(provider, token)).ReturnsAsync((IdentityUser)null);
            _emailManagerMock.Setup(manager => manager.FindByEmailAsync(existingUser.Email)).ReturnsAsync(existingUser);

            var result = await _userAccountService.ExternalLoginAsync(provider, token);

            Assert.False(result.Succeeded);
            Assert.Equal(RuntimeApps.Authentication.Shared.Models.ResultCode.BadRequest, result.Code);
            Assert.Equal("ExternalAuthenticationFailed", result.Errors.Single().Code);
            _loginManagerMock.Verify(manager => manager.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never());
            _emailManagerMock.Verify(manager => manager.FindByEmailAsync(It.IsAny<string>()), Times.Never());
        }

        [Fact]
        public async Task ExternalLogin_UntrustedEmailWithoutMatchingAccount_HasSameGenericFailure() {
            const string provider = "Google";
            const string token = "provider-token";
            var loginInfo = new UserLoginInfo(provider, token, provider);
            _externalLoginProvider1.SetupGet(item => item.Provider).Returns("Not Selected");
            _externalLoginProvider2.SetupGet(item => item.Provider).Returns(provider);
            _externalLoginProvider2.Setup(item => item.ValidateAsync(token))
                .ReturnsAsync(new RuntimeApps.Authentication.Features.ExternalLogin.Models.ExternalLoginProviderResult<IdentityUser> {
                    User = new IdentityUser { Email = "new@example.com" }, LoginInfo = loginInfo,
                    Email = "new@example.com", EmailVerified = false
                });
            _loginManagerMock.Setup(manager => manager.FindByLoginAsync(provider, token)).ReturnsAsync((IdentityUser)null);

            var result = await _userAccountService.ExternalLoginAsync(provider, token);

            Assert.False(result.Succeeded);
            Assert.Equal(RuntimeApps.Authentication.Shared.Models.ResultCode.BadRequest, result.Code);
            Assert.Equal("ExternalAuthenticationFailed", result.Errors.Single().Code);
            Assert.Equal("External authentication could not be completed.", result.Errors.Single().Description);
            _emailManagerMock.Verify(manager => manager.FindByEmailAsync(It.IsAny<string>()), Times.Never());
            _userManagerMock.Verify(manager => manager.CreateAsync(It.IsAny<IdentityUser>()), Times.Never());
        }

        [Fact]
        public async Task ExternalLogin_FailedLinkAfterCreateLeavesRetryableUserWithoutSession() {
            const string provider = "Google";
            const string token = "provider-token";
            var user = new IdentityUser { Email = "trusted@example.com", UserName = "trusted@example.com" };
            var loginInfo = new UserLoginInfo(provider, token, provider);
            _externalLoginProvider1.SetupGet(item => item.Provider).Returns("Not Selected");
            _externalLoginProvider2.SetupGet(item => item.Provider).Returns(provider);
            _externalLoginProvider2.Setup(item => item.ValidateAsync(token)).ReturnsAsync(
                new RuntimeApps.Authentication.Features.ExternalLogin.Models.ExternalLoginProviderResult<IdentityUser> {
                    User = user, LoginInfo = loginInfo, Email = user.Email, EmailVerified = true
                });
            _externalLoginEmailTrustPolicyMock.Setup(policy => policy.IsEmailTrusted(provider, It.IsAny<RuntimeApps.Authentication.Features.ExternalLogin.Models.ExternalLoginProviderResult<IdentityUser>>())).Returns(true);
            _loginManagerMock.Setup(manager => manager.FindByLoginAsync(provider, token)).ReturnsAsync((IdentityUser)null);
            _emailManagerMock.Setup(manager => manager.FindByEmailAsync(user.Email)).ReturnsAsync((IdentityUser)null);
            _userManagerMock.Setup(manager => manager.CreateAsync(user)).ReturnsAsync(IdentityResult.Success);
            _loginManagerMock.Setup(manager => manager.AddLoginAsync(user, loginInfo)).ReturnsAsync(IdentityResult.Failed());
            var result = await _userAccountService.ExternalLoginAsync(provider, token);

            Assert.False(result.Succeeded);
            _userManagerMock.Verify(manager => manager.CreateAsync(user), Times.Once);
            _userManagerMock.Verify(manager => manager.DeleteAsync(user), Times.Never);
            _loginManagerMock.Verify(manager => manager.AddLoginAsync(user, loginInfo), Times.Once);
            _sessionIssuerMock.Verify(issuer => issuer.IssueAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task ExternalLogin_CancellationAfterCreateFinishesLinkBeforeObservingCancellation() {
            const string provider = "Google";
            const string token = "provider-token";
            using var cancellation = new CancellationTokenSource();
            var user = new IdentityUser { Email = "trusted@example.com", UserName = "trusted@example.com" };
            var loginInfo = new UserLoginInfo(provider, token, provider);
            _externalLoginProvider1.SetupGet(item => item.Provider).Returns("Not Selected");
            _externalLoginProvider2.SetupGet(item => item.Provider).Returns(provider);
            _externalLoginProvider2.Setup(item => item.ValidateAsync(token, It.IsAny<CancellationToken>())).ReturnsAsync(
                new RuntimeApps.Authentication.Features.ExternalLogin.Models.ExternalLoginProviderResult<IdentityUser> {
                    User = user, LoginInfo = loginInfo, Email = user.Email, EmailVerified = true
                });
            _externalLoginEmailTrustPolicyMock.Setup(policy => policy.IsEmailTrusted(provider, It.IsAny<RuntimeApps.Authentication.Features.ExternalLogin.Models.ExternalLoginProviderResult<IdentityUser>>())).Returns(true);
            _loginManagerMock.Setup(manager => manager.FindByLoginAsync(provider, token)).ReturnsAsync((IdentityUser)null);
            _emailManagerMock.Setup(manager => manager.FindByEmailAsync(user.Email)).ReturnsAsync((IdentityUser)null);
            _userManagerMock.Setup(manager => manager.CreateAsync(user)).Returns(() => {
                cancellation.Cancel();
                return Task.FromResult(IdentityResult.Success);
            });
            _loginManagerMock.Setup(manager => manager.AddLoginAsync(user, loginInfo)).ReturnsAsync(IdentityResult.Success);

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                _userAccountService.ExternalLoginAsync(provider, token, cancellation.Token));

            _loginManagerMock.Verify(manager => manager.AddLoginAsync(user, loginInfo), Times.Once);
            _sessionIssuerMock.Verify(issuer => issuer.IssueAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task ExternalLogin_TrustedEmailCanLinkExistingAccount() {
            const string provider = "Google";
            const string token = "provider-token";
            var user = new IdentityUser { Email = "trusted@example.com", EmailConfirmed = true };
            var loginInfo = new UserLoginInfo(provider, token, provider);
            var expectedToken = new RuntimeApps.Authentication.Shared.Models.Token { AuthenticationToken = "access" };
            _externalLoginProvider1.SetupGet(item => item.Provider).Returns("Not Selected");
            _externalLoginProvider2.SetupGet(item => item.Provider).Returns(provider);
            _externalLoginProvider2.Setup(item => item.ValidateAsync(token)).ReturnsAsync(
                new RuntimeApps.Authentication.Features.ExternalLogin.Models.ExternalLoginProviderResult<IdentityUser> {
                    User = new IdentityUser { Email = user.Email }, LoginInfo = loginInfo,
                    Email = user.Email, EmailVerified = true
                });
            _externalLoginEmailTrustPolicyMock.Setup(policy => policy.IsEmailTrusted(provider, It.IsAny<RuntimeApps.Authentication.Features.ExternalLogin.Models.ExternalLoginProviderResult<IdentityUser>>())).Returns(true);
            _loginManagerMock.Setup(manager => manager.FindByLoginAsync(provider, token)).ReturnsAsync((IdentityUser)null);
            _emailManagerMock.Setup(manager => manager.FindByEmailAsync(user.Email)).ReturnsAsync(user);
            _loginManagerMock.Setup(manager => manager.AddLoginAsync(user, loginInfo)).ReturnsAsync(IdentityResult.Success);
            _sessionIssuerMock.Setup(issuer => issuer.IssueAsync(user, It.IsAny<CancellationToken>())).ReturnsAsync(expectedToken);

            var result = await _userAccountService.ExternalLoginAsync(provider, token);

            Assert.True(result.Succeeded);
            Assert.Same(user, result.Data);
            Assert.Same(expectedToken, result.Meta);
            _loginManagerMock.Verify(manager => manager.AddLoginAsync(user, loginInfo), Times.Once);
        }

        [Fact]
        public async Task ExternalLogin_UnverifiedEmail_DoesNotLinkExistingAccount() {
            const string provider = "Google";
            const string token = "provider-token";
            var user = new IdentityUser { Email = "existing@example.com", EmailConfirmed = true };
            var loginInfo = new UserLoginInfo(provider, token, provider);
            _externalLoginProvider1.SetupGet(item => item.Provider).Returns("Not Selected");
            _externalLoginProvider2.SetupGet(item => item.Provider).Returns(provider);
            _externalLoginProvider2.Setup(item => item.ValidateAsync(token))
                .ReturnsAsync(new RuntimeApps.Authentication.Features.ExternalLogin.Models.ExternalLoginProviderResult<IdentityUser> {
                    User = new IdentityUser { Email = user.Email }, LoginInfo = loginInfo,
                    Email = user.Email, EmailVerified = false
                });
            _loginManagerMock.Setup(manager => manager.FindByLoginAsync(provider, token)).ReturnsAsync((IdentityUser)null);
            _emailManagerMock.Setup(manager => manager.FindByEmailAsync(user.Email)).ReturnsAsync(user);

            var result = await _userAccountService.ExternalLoginAsync(provider, token);

            Assert.False(result.Succeeded);
            Assert.Equal(RuntimeApps.Authentication.Shared.Models.ResultCode.BadRequest, result.Code);
            Assert.Equal("ExternalAuthenticationFailed", result.Errors.Single().Code);
            _loginManagerMock.Verify(manager => manager.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never());
        }

        [Fact]
        public async Task ExternalLogin_CanRequireEmailVerificationWithoutIssuingToken() {
            const string provider = "Google";
            const string token = "provider-token";
            var user = new IdentityUser { Email = "new@example.com", UserName = "new@example.com" };
            var loginInfo = new UserLoginInfo(provider, token, provider);
            var expiresAt = DateTimeOffset.UtcNow.AddMinutes(10);
            var workflow = new Mock<IVerificationWorkflowService<IdentityUser, string>>();

            _externalLoginProvider1.SetupGet(item => item.Provider).Returns("Not Selected");
            _externalLoginProvider2.SetupGet(item => item.Provider).Returns(provider);
            _externalLoginProvider2.Setup(item => item.ValidateAsync(token))
                .ReturnsAsync(new RuntimeApps.Authentication.Features.ExternalLogin.Models.ExternalLoginProviderResult<IdentityUser> {
                    User = user, LoginInfo = loginInfo, Email = user.Email, EmailVerified = false
                });
            _loginManagerMock.Setup(manager => manager.FindByLoginAsync(provider, token)).ReturnsAsync(user);
            workflow.Setup(service => service.StartAsync(
                    user, RuntimeApps.Authentication.Features.Verification.Models.VerificationPurpose.Registration,
                    RuntimeApps.Authentication.Features.Verification.Models.VerificationChannel.Email, user.Email,
                    null, null, It.IsAny<CancellationToken>()))
                .ReturnsAsync(RuntimeApps.Authentication.Features.Verification.Models.VerificationOperationResult.Success("external-handle", expiresAt));

            var service = new UserAccountService<IdentityUser, string>(
                _userManagerMock.Object, _signInManagerMock.Object,
                new IExternalLoginProvider<IdentityUser>[] { _externalLoginProvider1.Object, _externalLoginProvider2.Object },
                _authenticationHandlerProviderMock.Object, _httpContextAccessorMock.Object,
                _userClaimsPrincipalFactoryMock.Object, _authenticationSchemeProviderMock.Object,
                null, null, null, _externalLoginEmailTrustPolicyMock.Object,
                Microsoft.Extensions.Options.Options.Create(new RuntimeApps.Authentication.Features.Verification.Models.VerificationOptions {
                    RequireEmailVerificationForExternalLogins = true
                }), workflow.Object, _loginManagerMock.Object, _emailManagerMock.Object, _sessionIssuerMock.Object);

            var result = await service.ExternalLoginAsync(provider, token);

            Assert.True(result.Succeeded);
            Assert.True(result.Meta.VerificationRequired);
            Assert.Equal("external-handle", result.Meta.VerificationHandle);
            Assert.Null(result.Meta.AuthenticationToken);
            _sessionIssuerMock.Verify(provider => provider.IssueAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task ExternalLogin_Success_ExistsLogin() {
            //Arrange
            string provider = "Google", token = "token";
            var user = new IdentityUser() {
                Email = "test@test.com"
            };
            var appToken = new RuntimeApps.Authentication.Shared.Models.Token() {
                AuthenticationToken = "",
                ExpireDate = DateTimeOffset.Now.AddDays(30),
            };
            var loginInfo = new UserLoginInfo(provider, token, provider);
            _externalLoginProvider1.SetupGet(e => e.Provider)
                .Returns("Not Selected Provided");
            _externalLoginProvider2.SetupGet(e => e.Provider)
                .Returns(provider);
            _externalLoginProvider2.Setup(e => e.ValidateAsync(token))
                .ReturnsAsync(new RuntimeApps.Authentication.Features.ExternalLogin.Models.ExternalLoginProviderResult<IdentityUser> {
                    User = user, LoginInfo = loginInfo, Email = user.Email, EmailVerified = false
                });
            _loginManagerMock.Setup(u => u.FindByLoginAsync(provider, token))
                .ReturnsAsync(user);
            _loginManagerMock.Setup(u => u.AddLoginAsync(user, loginInfo))
                .ReturnsAsync(IdentityResult.Success);
            _sessionIssuerMock.Setup(t => t.IssueAsync(user, It.IsAny<CancellationToken>()))
                .ReturnsAsync(appToken);

            //Act
            var result = await _userAccountService.ExternalLoginAsync(provider, token);

            //Assert
            result.Succeeded.Should().BeTrue();
            result.Data.Should().NotBeNull()
                .And.Be(user);
            result.Meta.Should().NotBeNull()
                .And.Be(appToken);
            _userManagerMock.Verify(u => u.CreateAsync(It.IsAny<IdentityUser>()), Times.Never());
            _loginManagerMock.Verify(u => u.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never());
        }


        [Fact]
        public async Task ExternalLogin_ProviderNotFound() {
            //Arrange
            string provider = "NotExistProvider", token = "token";
            var loginInfo = new UserLoginInfo(provider, token, provider);
            _externalLoginProvider1.SetupGet(e => e.Provider)
                .Returns("Provider1");
            _externalLoginProvider2.SetupGet(e => e.Provider)
                .Returns("Provider2");

            //Act
            var result = await _userAccountService.ExternalLoginAsync(provider, token);

            //Assert
            result.Succeeded.Should().BeFalse();
            result.Data.Should().BeNull();
            result.Meta.Should().BeNull();
            _userManagerMock.Verify(u => u.CreateAsync(It.IsAny<IdentityUser>()), Times.Never());
            _loginManagerMock.Verify(u => u.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never());
        }
    }
}
