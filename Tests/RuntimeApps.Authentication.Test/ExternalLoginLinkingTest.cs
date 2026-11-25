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
    /// <summary>Linking, unlinking and listing the external logins of an authenticated account.</summary>
    public class ExternalLoginLinkingTest {
        private const string Google = "GOOGLE";
        private const string Microsoft = "MICROSOFT";

        private readonly Mock<IExternalLoginProvider<IdentityUser>> _google = new();
        private readonly Mock<IExternalLoginProvider<IdentityUser>> _microsoft = new();
        private readonly Mock<IUserManager<IdentityUser>> _userManager = new();
        private readonly Mock<IUserLoginManager<IdentityUser>> _loginManager = new();
        private readonly Mock<IUserEmailManager<IdentityUser>> _emailManager = new();
        private readonly Mock<IUserPasswordManager<IdentityUser>> _passwordManager = new();
        private readonly Mock<ISignInManager<IdentityUser>> _signInManager = new();
        private readonly Mock<IRefreshTokenService<string>> _refreshTokens = new();
        private readonly IdentityUser _user = new() { Id = "user-1", Email = "owner@example.com", EmailConfirmed = true };
        private readonly List<UserLoginInfo> _logins = new();

        public ExternalLoginLinkingTest() {
            _google.SetupGet(p => p.Provider).Returns(Google);
            _microsoft.SetupGet(p => p.Provider).Returns(Microsoft);
            _loginManager.Setup(m => m.GetLoginsAsync(_user)).ReturnsAsync(() => _logins.ToList());
            _loginManager.Setup(m => m.AddLoginAsync(_user, It.IsAny<UserLoginInfo>())).ReturnsAsync(IdentityResult.Success);
            _loginManager.Setup(m => m.RemoveLoginAsync(_user, It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Success);
            _passwordManager.Setup(m => m.HasPasswordAsync(_user)).ReturnsAsync(true);
            _refreshTokens.Setup(s => s.RevokeAllAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(1);
        }

        private ExternalLoginService<IdentityUser, string> CreateService(IUserPasswordManager<IdentityUser> passwordManager = null) =>
            new(new[] { _google.Object, _microsoft.Object },
                _userManager.Object, _loginManager.Object, _emailManager.Object,
                passwordManager ?? _passwordManager.Object,
                _signInManager.Object,
                Mock.Of<IExternalLoginEmailTrustPolicy<IdentityUser>>(),
                Options.Create(new VerificationOptions()),
                _refreshTokens.Object);

        private void Validates(Mock<IExternalLoginProvider<IdentityUser>> provider, string token, string providerName, string subject, string email = null) =>
            provider.Setup(p => p.ValidateAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new ExternalLoginProviderResult<IdentityUser> {
                    User = new IdentityUser { Email = email }, LoginInfo = new UserLoginInfo(providerName, subject, providerName), Email = email
                });

        private void PasswordIs(string password, bool correct) =>
            _signInManager.Setup(m => m.CheckPasswordSignInAsync(_user, password, true))
                .ReturnsAsync(correct ? SignInResult.Success : SignInResult.Failed);

        private static LinkExternalLoginModel LinkWithPassword(string provider = Microsoft, string token = "new-token", string password = "correct") =>
            new() { Provider = provider, Token = token, CurrentPassword = password };

        private static void AssertFailure(Result result, ResultCode code, string errorCode) {
            Assert.False(result.Succeeded);
            Assert.Equal(code, result.Code);
            Assert.Equal(errorCode, Assert.Single(result.Errors).Code);
        }

        // ---------- Link ----------

        [Theory]
        [InlineData(null, "token")]
        [InlineData("", "token")]
        [InlineData(Microsoft, null)]
        [InlineData(Microsoft, " ")]
        public async Task Link_MissingProviderOrToken_IsBadRequest(string provider, string token) {
            var result = await CreateService().LinkAsync(_user, new LinkExternalLoginModel { Provider = provider, Token = token, CurrentPassword = "correct" });

            AssertFailure(result, ResultCode.BadRequest, "InvalidExternalLogin");
            _loginManager.Verify(m => m.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never);
        }

        [Fact]
        public async Task Link_WithoutReauthentication_IsForbidden() {
            Validates(_microsoft, "new-token", Microsoft, "tenant:oid");

            var result = await CreateService().LinkAsync(_user, new LinkExternalLoginModel { Provider = Microsoft, Token = "new-token" });

            AssertFailure(result, ResultCode.Forbidden, "ReauthenticationRequired");
            _microsoft.Verify(p => p.ValidateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            _loginManager.Verify(m => m.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never);
        }

        [Fact]
        public async Task Link_WrongPassword_IsForbiddenAndCountsTowardLockout() {
            Validates(_microsoft, "new-token", Microsoft, "tenant:oid");
            PasswordIs("wrong", correct: false);

            var result = await CreateService().LinkAsync(_user, LinkWithPassword(password: "wrong"));

            AssertFailure(result, ResultCode.Forbidden, "ReauthenticationRequired");
            _signInManager.Verify(m => m.CheckPasswordSignInAsync(_user, "wrong", true), Times.Once);
            _loginManager.Verify(m => m.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never);
        }

        [Fact]
        public async Task Link_PasswordSuppliedButAccountHasNoPassword_IsForbiddenWithoutPasswordCheck() {
            _passwordManager.Setup(m => m.HasPasswordAsync(_user)).ReturnsAsync(false);
            Validates(_microsoft, "new-token", Microsoft, "tenant:oid");

            var result = await CreateService().LinkAsync(_user, LinkWithPassword());

            AssertFailure(result, ResultCode.Forbidden, "ReauthenticationRequired");
            _signInManager.Verify(m => m.CheckPasswordSignInAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<bool>()), Times.Never);
        }

        [Fact]
        public async Task Link_CorrectPassword_LinksIdentity() {
            var identity = new UserLoginInfo(Microsoft, "tenant:oid", Microsoft);
            Validates(_microsoft, "new-token", Microsoft, "tenant:oid");
            PasswordIs("correct", correct: true);

            var result = await CreateService().LinkAsync(_user, LinkWithPassword());

            Assert.True(result.Succeeded);
            _loginManager.Verify(m => m.AddLoginAsync(_user, It.Is<UserLoginInfo>(l =>
                l.LoginProvider == identity.LoginProvider && l.ProviderKey == identity.ProviderKey)), Times.Once);
        }

        [Fact]
        public async Task Link_DoesNotRequireProviderEmailToMatchAndDoesNotCopyIt() {
            Validates(_microsoft, "new-token", Microsoft, "tenant:oid", email: "different@other.example");
            PasswordIs("correct", correct: true);

            var result = await CreateService().LinkAsync(_user, LinkWithPassword());

            Assert.True(result.Succeeded);
            Assert.Equal("owner@example.com", _user.Email);
            _userManager.Verify(m => m.UpdateAsync(It.IsAny<IdentityUser>()), Times.Never);
            _emailManager.Verify(m => m.FindByEmailAsync(It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task Link_ReauthenticatedByAlreadyLinkedProviderToken_LinksIdentity() {
            _logins.Add(new UserLoginInfo(Google, "google-sub", Google));
            Validates(_google, "fresh-google", Google, "google-sub");
            Validates(_microsoft, "new-token", Microsoft, "tenant:oid");

            var result = await CreateService().LinkAsync(_user, new LinkExternalLoginModel {
                Provider = Microsoft, Token = "new-token", ReauthenticationProvider = Google, ReauthenticationToken = "fresh-google"
            });

            Assert.True(result.Succeeded);
            _signInManager.Verify(m => m.CheckPasswordSignInAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<bool>()), Times.Never);
        }

        [Fact]
        public async Task Link_ReauthenticationTokenOfAnotherSubject_IsForbidden() {
            _logins.Add(new UserLoginInfo(Google, "google-sub", Google));
            Validates(_google, "someone-else", Google, "other-sub");
            Validates(_microsoft, "new-token", Microsoft, "tenant:oid");

            var result = await CreateService().LinkAsync(_user, new LinkExternalLoginModel {
                Provider = Microsoft, Token = "new-token", ReauthenticationProvider = Google, ReauthenticationToken = "someone-else"
            });

            AssertFailure(result, ResultCode.Forbidden, "ReauthenticationRequired");
            _loginManager.Verify(m => m.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never);
        }

        [Fact]
        public async Task Link_ReauthenticationProviderNotLinkedToAccount_IsForbidden() {
            Validates(_google, "fresh-google", Google, "google-sub");
            Validates(_microsoft, "new-token", Microsoft, "tenant:oid");

            var result = await CreateService().LinkAsync(_user, new LinkExternalLoginModel {
                Provider = Microsoft, Token = "new-token", ReauthenticationProvider = Google, ReauthenticationToken = "fresh-google"
            });

            AssertFailure(result, ResultCode.Forbidden, "ReauthenticationRequired");
        }

        [Fact]
        public async Task Link_InvalidOrUnknownReauthenticationProvider_IsForbidden() {
            _logins.Add(new UserLoginInfo(Google, "google-sub", Google));
            _google.Setup(p => p.ValidateAsync("bad", It.IsAny<CancellationToken>())).ReturnsAsync((ExternalLoginProviderResult<IdentityUser>)null);

            var invalidToken = await CreateService().LinkAsync(_user, new LinkExternalLoginModel {
                Provider = Microsoft, Token = "new-token", ReauthenticationProvider = Google, ReauthenticationToken = "bad"
            });
            var unknownProvider = await CreateService().LinkAsync(_user, new LinkExternalLoginModel {
                Provider = Microsoft, Token = "new-token", ReauthenticationProvider = "Nope", ReauthenticationToken = "x"
            });

            AssertFailure(invalidToken, ResultCode.Forbidden, "ReauthenticationRequired");
            AssertFailure(unknownProvider, ResultCode.Forbidden, "ReauthenticationRequired");
        }

        [Fact]
        public async Task Link_UnknownProvider_IsGenericBadRequest() {
            PasswordIs("correct", correct: true);

            var result = await CreateService().LinkAsync(_user, LinkWithPassword(provider: "Nope"));

            AssertFailure(result, ResultCode.BadRequest, "ExternalAuthenticationFailed");
        }

        [Fact]
        public async Task Link_InvalidProviderToken_IsGenericBadRequest() {
            PasswordIs("correct", correct: true);
            _microsoft.Setup(p => p.ValidateAsync("new-token", It.IsAny<CancellationToken>())).ReturnsAsync((ExternalLoginProviderResult<IdentityUser>)null);

            var result = await CreateService().LinkAsync(_user, LinkWithPassword());

            AssertFailure(result, ResultCode.BadRequest, "ExternalAuthenticationFailed");
            _loginManager.Verify(m => m.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never);
        }

        [Fact]
        public async Task Link_SecondIdentityForSameProvider_IsConflict() {
            _logins.Add(new UserLoginInfo(Microsoft, "tenant:first", Microsoft));
            Validates(_microsoft, "new-token", Microsoft, "tenant:second");
            PasswordIs("correct", correct: true);

            var result = await CreateService().LinkAsync(_user, LinkWithPassword());

            AssertFailure(result, ResultCode.Conflict, "ExternalLoginConflict");
            _loginManager.Verify(m => m.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never);
        }

        [Fact]
        public async Task Link_IdentityBelongsToAnotherAccount_IsConflict() {
            Validates(_microsoft, "new-token", Microsoft, "tenant:oid");
            PasswordIs("correct", correct: true);
            _loginManager.Setup(m => m.AddLoginAsync(_user, It.IsAny<UserLoginInfo>()))
                .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "LoginAlreadyAssociated" }));

            var result = await CreateService().LinkAsync(_user, LinkWithPassword());

            AssertFailure(result, ResultCode.Conflict, "ExternalLoginConflict");
        }

        [Fact]
        public async Task Link_OtherStoreFailure_IsGenericBadRequestWithoutIdentityDetail() {
            Validates(_microsoft, "new-token", Microsoft, "tenant:oid");
            PasswordIs("correct", correct: true);
            _loginManager.Setup(m => m.AddLoginAsync(_user, It.IsAny<UserLoginInfo>()))
                .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "Db", Description = "private db detail" }));

            var result = await CreateService().LinkAsync(_user, LinkWithPassword());

            AssertFailure(result, ResultCode.BadRequest, "ExternalAuthenticationFailed");
            Assert.DoesNotContain("private db detail", result.Errors.Single().Description);
        }

        [Fact]
        public async Task Link_ConcurrentLinksOfSameProvider_AreUndoneAndReportedAsConflict() {
            Validates(_microsoft, "new-token", Microsoft, "tenant:oid");
            PasswordIs("correct", correct: true);
            var calls = 0;
            _loginManager.Setup(m => m.GetLoginsAsync(_user)).ReturnsAsync(() => {
                calls++;
                return calls == 1
                    ? new List<UserLoginInfo>()
                    : new List<UserLoginInfo> {
                        new UserLoginInfo(Microsoft, "tenant:other-request", Microsoft),
                        new UserLoginInfo(Microsoft, "tenant:oid", Microsoft)
                    };
            });

            var result = await CreateService().LinkAsync(_user, LinkWithPassword());

            AssertFailure(result, ResultCode.Conflict, "ExternalLoginConflict");
            _loginManager.Verify(m => m.RemoveLoginAsync(_user, Microsoft, "tenant:oid"), Times.Once);
        }

        [Fact]
        public async Task Link_Cancelled_ThrowsBeforeAnyCheckOrWrite() {
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                CreateService().LinkAsync(_user, LinkWithPassword(), cancellation.Token));

            _signInManager.Verify(m => m.CheckPasswordSignInAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<bool>()), Times.Never);
            _loginManager.Verify(m => m.AddLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<UserLoginInfo>()), Times.Never);
        }

        // ---------- Unlink ----------

        [Fact]
        public async Task Unlink_BlankProvider_IsBadRequest() {
            var result = await CreateService().UnlinkAsync(_user, " ");

            AssertFailure(result, ResultCode.BadRequest, "InvalidExternalLogin");
        }

        [Fact]
        public async Task Unlink_ProviderNotLinked_IsBadRequest() {
            _logins.Add(new UserLoginInfo(Google, "google-sub", Google));

            var result = await CreateService().UnlinkAsync(_user, Microsoft);

            AssertFailure(result, ResultCode.BadRequest, "ExternalLoginNotLinked");
            _loginManager.Verify(m => m.RemoveLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task Unlink_AmbiguousDuplicateProviderRows_IsConflict() {
            _logins.Add(new UserLoginInfo(Google, "a", Google));
            _logins.Add(new UserLoginInfo(Google, "b", Google));

            var result = await CreateService().UnlinkAsync(_user, Google);

            AssertFailure(result, ResultCode.Conflict, "ExternalLoginAmbiguous");
            _loginManager.Verify(m => m.RemoveLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task Unlink_OnlyLoginButAccountHasPassword_RemovesLoginAndRevokesSessions() {
            _logins.Add(new UserLoginInfo(Google, "google-sub", Google));
            _loginManager.Setup(m => m.RemoveLoginAsync(_user, Google, "google-sub")).Returns(() => {
                _logins.Clear();
                return Task.FromResult(IdentityResult.Success);
            });

            var result = await CreateService().UnlinkAsync(_user, "google");

            Assert.True(result.Succeeded);
            _loginManager.Verify(m => m.RemoveLoginAsync(_user, Google, "google-sub"), Times.Once);
            _refreshTokens.Verify(s => s.RevokeAllAsync("user-1", It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Unlink_NoPasswordButAnotherUsableLogin_Succeeds() {
            _passwordManager.Setup(m => m.HasPasswordAsync(_user)).ReturnsAsync(false);
            _logins.Add(new UserLoginInfo(Google, "google-sub", Google));
            _logins.Add(new UserLoginInfo(Microsoft, "tenant:oid", Microsoft));
            _loginManager.Setup(m => m.RemoveLoginAsync(_user, Google, "google-sub")).Returns(() => {
                _logins.RemoveAll(l => l.LoginProvider == Google);
                return Task.FromResult(IdentityResult.Success);
            });

            var result = await CreateService().UnlinkAsync(_user, Google);

            Assert.True(result.Succeeded);
        }

        [Fact]
        public async Task Unlink_LastAuthenticationMethod_IsConflictAndNothingIsRemoved() {
            _passwordManager.Setup(m => m.HasPasswordAsync(_user)).ReturnsAsync(false);
            _logins.Add(new UserLoginInfo(Google, "google-sub", Google));

            var result = await CreateService().UnlinkAsync(_user, Google);

            AssertFailure(result, ResultCode.Conflict, "LastAuthenticationMethod");
            _loginManager.Verify(m => m.RemoveLoginAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
            _refreshTokens.Verify(s => s.RevokeAllAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Unlink_RemainingLoginUsesUnregisteredProvider_DoesNotCountAsUsable() {
            _passwordManager.Setup(m => m.HasPasswordAsync(_user)).ReturnsAsync(false);
            _logins.Add(new UserLoginInfo(Google, "google-sub", Google));
            _logins.Add(new UserLoginInfo("RETIRED", "old", "RETIRED"));

            var result = await CreateService().UnlinkAsync(_user, Google);

            AssertFailure(result, ResultCode.Conflict, "LastAuthenticationMethod");
        }

        [Fact]
        public async Task Unlink_CustomPasswordManagerWithoutHasPassword_FailsClosed() {
            _logins.Add(new UserLoginInfo(Google, "google-sub", Google));

            var result = await CreateService(new LegacyPasswordManager()).UnlinkAsync(_user, Google);

            AssertFailure(result, ResultCode.Conflict, "LastAuthenticationMethod");
        }

        [Fact]
        public async Task Unlink_StoreRemovalFails_IsBadRequest() {
            _logins.Add(new UserLoginInfo(Google, "google-sub", Google));
            _loginManager.Setup(m => m.RemoveLoginAsync(_user, Google, "google-sub")).ReturnsAsync(IdentityResult.Failed());

            var result = await CreateService().UnlinkAsync(_user, Google);

            AssertFailure(result, ResultCode.BadRequest, "ExternalLoginNotUnlinked");
            _refreshTokens.Verify(s => s.RevokeAllAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Unlink_ConcurrentUnlinkLeavesNoMethod_RestoresLoginAndReportsConflict() {
            // Both requests passed the first check; by the re-check the other one has removed the password.
            var hasPasswordCalls = 0;
            _passwordManager.Setup(m => m.HasPasswordAsync(_user)).ReturnsAsync(() => ++hasPasswordCalls == 1);
            _logins.Add(new UserLoginInfo(Google, "google-sub", Google));
            _logins.Add(new UserLoginInfo(Microsoft, "tenant:oid", Microsoft));
            _loginManager.Setup(m => m.RemoveLoginAsync(_user, Google, "google-sub")).Returns(() => {
                _logins.RemoveAll(l => l.LoginProvider == Google);
                _logins.RemoveAll(l => l.LoginProvider == Microsoft);
                return Task.FromResult(IdentityResult.Success);
            });

            var result = await CreateService().UnlinkAsync(_user, Google);

            AssertFailure(result, ResultCode.Conflict, "LastAuthenticationMethod");
            _loginManager.Verify(m => m.AddLoginAsync(_user, It.Is<UserLoginInfo>(l => l.LoginProvider == Google && l.ProviderKey == "google-sub")), Times.Once);
            _refreshTokens.Verify(s => s.RevokeAllAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------- List ----------

        [Fact]
        public async Task List_ReturnsProvidersOnlyAndNeverSubjectKeys() {
            _logins.Add(new UserLoginInfo(Google, "secret-subject", Google));
            _logins.Add(new UserLoginInfo(Microsoft, "tenant:oid", Microsoft));

            var logins = await CreateService().ListLoginsAsync(_user);

            Assert.Equal(new[] { Google, Microsoft }, logins.Select(l => l.Provider));
            Assert.Equal(new[] { nameof(ExternalLoginSummary.Provider) },
                typeof(ExternalLoginSummary).GetProperties().Select(p => p.Name));
        }

        [Fact]
        public async Task List_NoLogins_ReturnsEmpty() {
            Assert.Empty(await CreateService().ListLoginsAsync(_user));
        }

        // ---------- Compatibility ----------

        [Fact]
        public async Task PasswordManagerWithoutHasPassword_DefaultsToFalse() {
            IUserPasswordManager<IdentityUser> manager = new LegacyPasswordManager();

            Assert.False(await manager.HasPasswordAsync(_user));
        }

        private sealed class LegacyPasswordManager : IUserPasswordManager<IdentityUser> {
            public Task<bool> CheckPasswordAsync(IdentityUser user, string password) => Task.FromResult(true);
            public Task<IdentityResult> AddPasswordAsync(IdentityUser user, string password) => Task.FromResult(IdentityResult.Success);
            public Task<IdentityResult> ChangePasswordAsync(IdentityUser user, string currentPassword, string newPassword) => Task.FromResult(IdentityResult.Success);
            public Task<IdentityResult> RemovePasswordAsync(IdentityUser user) => Task.FromResult(IdentityResult.Success);
            public Task<string> GeneratePasswordResetTokenAsync(IdentityUser user) => Task.FromResult("token");
            public Task<IdentityResult> ResetPasswordAsync(IdentityUser user, string token, string newPassword) => Task.FromResult(IdentityResult.Success);
        }
    }
}
