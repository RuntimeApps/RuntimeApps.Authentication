using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Moq;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Service;

namespace RuntimeApps.Authentication.Test {
    public class UserAccountServiceTest {
        private const IdentityUser nullUSer = null;
        private readonly Mock<IUserManager<IdentityUser>> _userManagerMock;
        private readonly Mock<ISignInManager<IdentityUser>> _signInManagerMock;
        private readonly Mock<IJwtProvider<IdentityUser>> _jwtProviderMock;
        private readonly Mock<IExternalLoginProvider<IdentityUser>> _externalLoginProvider1;
        private readonly Mock<IExternalLoginProvider<IdentityUser>> _externalLoginProvider2;
        private readonly IUserAccountService<IdentityUser> _userAccountService;

        public UserAccountServiceTest() {
            _userManagerMock = new Mock<IUserManager<IdentityUser>>();
            _signInManagerMock = new Mock<ISignInManager<IdentityUser>>();
            _jwtProviderMock = new Mock<IJwtProvider<IdentityUser>>();
            _externalLoginProvider1 = new Mock<IExternalLoginProvider<IdentityUser>>();
            _externalLoginProvider2 = new Mock<IExternalLoginProvider<IdentityUser>>();
            _userAccountService = new UserAccountService<IdentityUser, string>(_userManagerMock.Object, _signInManagerMock.Object, _jwtProviderMock.Object, new IExternalLoginProvider<IdentityUser>[] {
                _externalLoginProvider1.Object,
                _externalLoginProvider2.Object
            });
        }

        [Fact]
        public async Task Login_Success() {
            //Arrange
            string userName = "userName", password = "password";
            var user = new IdentityUser() {
                Id = "userId",
                UserName = userName,
            };
            var token = new Model.Token() {
                AuthenticationToken = "",
                ExpireDate = DateTimeOffset.Now.AddDays(30),
            };
            _userManagerMock.Setup(u => u.FindByNameAsync(userName))
                .ReturnsAsync(user);
            _signInManagerMock.Setup(S => S.PasswordSignInAsync(user, password, It.IsAny<bool>(), It.IsAny<bool>()))
                .ReturnsAsync(SignInResult.Success);
            _jwtProviderMock.Setup(t => t.GenerateTokenAsync(user))
                .Returns(token);

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
        public async Task Register_Success() {
            //Arrange
            string password = "password";
            var user = new IdentityUser() {
                Email = "test@test.com"
            };
            var token = new Model.Token() {
                AuthenticationToken = "",
                ExpireDate = DateTimeOffset.Now.AddDays(30),
            };
            _userManagerMock.Setup(u => u.FindByNameAsync(user.Email))
                .ReturnsAsync(nullUSer);
            _userManagerMock.Setup(u => u.CreateAsync(user, password))
                .ReturnsAsync(IdentityResult.Success);
            _jwtProviderMock.Setup(t => t.GenerateTokenAsync(user))
                .Returns(token);

            //Act
            var result = await _userAccountService.RegisterAsync(user, password);

            //Assert
            result.Succeeded.Should().BeTrue();
            result.Data.Should().NotBeNull()
                .And.Be(user);
            result.Data.UserName.Should().Be(result.Data.Email);
            result.Meta.Should().NotBeNull()
                .And.Be(token);
        }

        [Fact]
        public async Task Register_UserExist() {
            //Arrange
            string password = "password";
            var user = new IdentityUser() {
                Email = "test@test.com"
            };
            _userManagerMock.Setup(u => u.FindByNameAsync(user.Email))
                .ReturnsAsync((IdentityUser)user);

            //Act
            var result = await _userAccountService.RegisterAsync(user, password);

            //Assert
            result.Succeeded.Should().BeFalse();
            result.Data.Should().BeNull();
            result.Meta.Should().BeNull();
        }

        [Fact]
        public async Task Register_ValidateError() {
            //Arrange
            string password = "password";
            var user = new IdentityUser() {
                Email = "test@test.com"
            };
            _userManagerMock.Setup(u => u.FindByNameAsync(user.Email))
                .ReturnsAsync(nullUSer);
            _userManagerMock.Setup(u => u.CreateAsync(user, password))
                .ReturnsAsync(IdentityResult.Failed(new IdentityError[] {
                    new IdentityError {
                        Code = "InvalidPassword",
                        Description = "Password must be more than 6 character"
                    }
                }));

            //Act
            var result = await _userAccountService.RegisterAsync(user, password);

            //Assert
            result.Succeeded.Should().BeFalse();
            result.Data.Should().BeNull();
            result.Meta.Should().BeNull();
        }

        [Fact]
        public async Task ExternalLogin_Success_CreateNewUser() {
            //Arrange
            string provider = "Google", token = "token";
            var user = new IdentityUser() {
                Email = "test@test.com"
            };
            var appToken = new Model.Token() {
                AuthenticationToken = "",
                ExpireDate = DateTimeOffset.Now.AddDays(30),
            };
            var loginInfo = new UserLoginInfo(provider, token, provider);
            _externalLoginProvider1.SetupGet(e => e.Provider)
                .Returns("Not Selected Provided");
            _externalLoginProvider2.SetupGet(e => e.Provider)
                .Returns(provider);
            _externalLoginProvider2.Setup(e => e.ValidateAsync(token))
                .ReturnsAsync((user, loginInfo));
            _userManagerMock.Setup(u => u.FindByLoginAsync(provider, token))
                .ReturnsAsync(nullUSer);
            _userManagerMock.Setup(u => u.FindByEmailAsync(user.Email))
                .ReturnsAsync(nullUSer);
            _userManagerMock.Setup(u => u.CreateAsync(user))
                .ReturnsAsync(IdentityResult.Success);
            _userManagerMock.Setup(u => u.AddLoginAsync(user, loginInfo))
                .ReturnsAsync(IdentityResult.Success);
            _jwtProviderMock.Setup(t => t.GenerateTokenAsync(user))
                .Returns(appToken);

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
        public async Task ExternalLogin_Success_ExistUser() {
            //Arrange
            string provider = "Google", token = "token";
            var user = new IdentityUser() {
                Email = "test@test.com"
            };
            var appToken = new Model.Token() {
                AuthenticationToken = "",
                ExpireDate = DateTimeOffset.Now.AddDays(30),
            };
            var loginInfo = new UserLoginInfo(provider, token, provider);
            _externalLoginProvider1.SetupGet(e => e.Provider)
                .Returns("Not Selected Provided");
            _externalLoginProvider2.SetupGet(e => e.Provider)
                .Returns(provider);
            _externalLoginProvider2.Setup(e => e.ValidateAsync(token))
                .ReturnsAsync((user, loginInfo));
            _userManagerMock.Setup(u => u.FindByLoginAsync(provider, token))
                .ReturnsAsync(nullUSer);
            _userManagerMock.Setup(u => u.FindByEmailAsync(user.Email))
                .ReturnsAsync(user);
            _userManagerMock.Setup(u => u.AddLoginAsync(user, loginInfo))
                .ReturnsAsync(IdentityResult.Success);
            _jwtProviderMock.Setup(t => t.GenerateTokenAsync(user))
                .Returns(appToken);

            //Act
            var result = await _userAccountService.ExternalLoginAsync(provider, token);

            //Assert
            result.Succeeded.Should().BeTrue();
            result.Data.Should().NotBeNull()
                .And.Be(user);
            result.Meta.Should().NotBeNull()
                .And.Be(appToken);
            _userManagerMock.Verify(u => u.CreateAsync(It.IsAny<IdentityUser>()), Times.Never());
            _userManagerMock.Verify(u => u.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Once());
        }

        [Fact]
        public async Task ExternalLogin_Success_ExistsLogin() {
            //Arrange
            string provider = "Google", token = "token";
            var user = new IdentityUser() {
                Email = "test@test.com"
            };
            var appToken = new Model.Token() {
                AuthenticationToken = "",
                ExpireDate = DateTimeOffset.Now.AddDays(30),
            };
            var loginInfo = new UserLoginInfo(provider, token, provider);
            _externalLoginProvider1.SetupGet(e => e.Provider)
                .Returns("Not Selected Provided");
            _externalLoginProvider2.SetupGet(e => e.Provider)
                .Returns(provider);
            _externalLoginProvider2.Setup(e => e.ValidateAsync(token))
                .ReturnsAsync((user, loginInfo));
            _userManagerMock.Setup(u => u.FindByLoginAsync(provider, token))
                .ReturnsAsync(user);
            _userManagerMock.Setup(u => u.AddLoginAsync(user, loginInfo))
                .ReturnsAsync(IdentityResult.Success);
            _jwtProviderMock.Setup(t => t.GenerateTokenAsync(user))
                .Returns(appToken);

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
