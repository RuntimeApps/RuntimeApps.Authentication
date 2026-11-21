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
        private readonly Mock<ISignInManager<IdentityUser>> _signInManagerMock;
        private readonly Mock<IJwtProvider<IdentityUser>> _jwtProviderMock;
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
            _signInManagerMock = new Mock<ISignInManager<IdentityUser>>();
            _jwtProviderMock = new Mock<IJwtProvider<IdentityUser>>();
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
            _jwtProviderMock.Object, null, null, _externalLoginEmailTrustPolicyMock.Object);

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
            _jwtProviderMock.Setup(t => t.GenerateTokenAsync(user))
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
        public async Task CompleteRegistration_Success_ConfirmedUser() {
            var user = new IdentityUser { Email = "test@test.com", EmailConfirmed = true };
            var token = new RuntimeApps.Authentication.Shared.Models.Token {
                AuthenticationToken = "",
                ExpireDate = DateTimeOffset.Now.AddDays(30),
            };
            _jwtProviderMock.Setup(provider => provider.GenerateTokenAsync(user)).ReturnsAsync(token);

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
            _jwtProviderMock.Verify(provider => provider.GenerateTokenAsync(It.IsAny<IdentityUser>()), Times.Never());
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
            _userManagerMock.Setup(u => u.FindByLoginAsync(provider, token))
                .ReturnsAsync(nullUSer);
            _userManagerMock.Setup(u => u.FindByEmailAsync(user.Email))
                .ReturnsAsync(nullUSer);
            _userManagerMock.Setup(u => u.CreateAsync(user))
                .ReturnsAsync(IdentityResult.Success);
            _userManagerMock.Setup(u => u.AddLoginAsync(user, loginInfo))
                .ReturnsAsync(IdentityResult.Success);
            _jwtProviderMock.Setup(t => t.GenerateTokenAsync(user))
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
            _userManagerMock.Verify(u => u.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Once());
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
            _userManagerMock.Setup(manager => manager.FindByLoginAsync(provider, token)).ReturnsAsync((IdentityUser)null);
            _userManagerMock.Setup(manager => manager.FindByEmailAsync(existingUser.Email)).ReturnsAsync(existingUser);

            var result = await _userAccountService.ExternalLoginAsync(provider, token);

            Assert.False(result.Succeeded);
            Assert.Equal(RuntimeApps.Authentication.Shared.Models.ResultCode.Conflict, result.Code);
            _userManagerMock.Verify(manager => manager.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never());
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
            _userManagerMock.Setup(manager => manager.FindByLoginAsync(provider, token)).ReturnsAsync((IdentityUser)null);
            _userManagerMock.Setup(manager => manager.FindByEmailAsync(user.Email)).ReturnsAsync(user);

            var result = await _userAccountService.ExternalLoginAsync(provider, token);

            Assert.False(result.Succeeded);
            Assert.Equal(RuntimeApps.Authentication.Shared.Models.ResultCode.Conflict, result.Code);
            _userManagerMock.Verify(manager => manager.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never());
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
            _userManagerMock.Setup(manager => manager.FindByLoginAsync(provider, token)).ReturnsAsync((IdentityUser)null);
            _userManagerMock.Setup(manager => manager.FindByEmailAsync(user.Email)).ReturnsAsync((IdentityUser)null);
            _userManagerMock.Setup(manager => manager.CreateAsync(user)).ReturnsAsync(IdentityResult.Success);
            _userManagerMock.Setup(manager => manager.AddLoginAsync(user, loginInfo)).ReturnsAsync(IdentityResult.Success);
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
                _jwtProviderMock.Object, null, null, _externalLoginEmailTrustPolicyMock.Object,
                Microsoft.Extensions.Options.Options.Create(new RuntimeApps.Authentication.Features.Verification.Models.VerificationOptions {
                    RequireEmailVerificationForExternalLogins = true
                }), workflow.Object);

            var result = await service.ExternalLoginAsync(provider, token);

            Assert.True(result.Succeeded);
            Assert.True(result.Meta.VerificationRequired);
            Assert.Equal("external-handle", result.Meta.VerificationHandle);
            Assert.Null(result.Meta.AuthenticationToken);
            _jwtProviderMock.Verify(provider => provider.GenerateTokenAsync(It.IsAny<IdentityUser>()), Times.Never());
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
            _userManagerMock.Setup(u => u.FindByLoginAsync(provider, token))
                .ReturnsAsync(user);
            _userManagerMock.Setup(u => u.AddLoginAsync(user, loginInfo))
                .ReturnsAsync(IdentityResult.Success);
            _jwtProviderMock.Setup(t => t.GenerateTokenAsync(user))
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
            _userManagerMock.Verify(u => u.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never());
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
            _userManagerMock.Verify(u => u.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never());
        }
    }
}
