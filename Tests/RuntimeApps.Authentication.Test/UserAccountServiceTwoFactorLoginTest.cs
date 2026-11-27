using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Moq;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.Account.Services;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

/// <summary>How password login hands over to the second step.</summary>
public class UserAccountServiceTwoFactorLoginTest {
    private static readonly DateTimeOffset Expires = new(2026, 1, 1, 9, 5, 0, TimeSpan.Zero);

    private readonly IdentityUser _user = new() { UserName = "mfa-user", EmailConfirmed = true };
    private readonly Mock<IUserManager<IdentityUser>> _users = new();
    private readonly Mock<IUserLockoutManager<IdentityUser>> _lockout;
    private readonly Mock<ISignInManager<IdentityUser>> _signIn = new();
    private readonly Mock<IAuthenticationSessionIssuer<IdentityUser>> _issuer = new();
    private readonly Mock<ITwoFactorLoginService<IdentityUser>> _twoFactor = new();

    public UserAccountServiceTwoFactorLoginTest() {
        _lockout = _users.As<IUserLockoutManager<IdentityUser>>();
        _users.Setup(m => m.FindByNameAsync(_user.UserName)).ReturnsAsync(_user);
        _signIn.Setup(m => m.PasswordSignInAsync(_user, "password", false, true)).ReturnsAsync(SignInResult.TwoFactorRequired);
        _issuer.Setup(i => i.IssueAsync(_user, It.IsAny<CancellationToken>())).ReturnsAsync(new Token { AuthenticationToken = "access-token" });
    }

    private UserAccountService<IdentityUser, string> Service(ITwoFactorLoginService<IdentityUser> twoFactor) =>
        new(_users.Object, _signIn.Object, Array.Empty<IExternalLoginProvider<IdentityUser>>(),
            Mock.Of<IAuthenticationHandlerProvider>(), Mock.Of<IHttpContextAccessor>(),
            Mock.Of<IUserClaimsPrincipalFactory<IdentityUser>>(), Mock.Of<IAuthenticationSchemeProvider>(),
            null, null, null, null, null, null, null, null, _issuer.Object, null, twoFactor);

    [Fact]
    public async Task TwoFactorRequired_ReturnsAcceptedWithChallenge_AndNoSession() {
        IReadOnlyList<TwoFactorMethodInfo> methods = [new TwoFactorMethodInfo("authenticator", false)];
        _twoFactor.Setup(s => s.BeginAsync(_user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(TwoFactorLoginStart.Required("handle-1", Expires, methods));

        var result = await Service(_twoFactor.Object).LoginAsync(_user.UserName, "password");

        Assert.False(result.Succeeded);
        Assert.Equal(ResultCode.Accepted, result.Code);
        Assert.Null(result.Data);
        Assert.Equal("handle-1", result.Meta.TwoFactorChallenge);
        Assert.Equal(Expires, result.Meta.TwoFactorExpiresAt);
        Assert.Equal("authenticator", Assert.Single(result.Meta.TwoFactorMethods).Name);
        Assert.Null(result.Meta.AuthenticationToken);
        _issuer.Verify(i => i.IssueAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task NoEnrolledMethod_WithRequireBehavior_ReturnsAcceptedWithEmptyMethods() {
        _twoFactor.Setup(s => s.BeginAsync(_user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(TwoFactorLoginStart.Required("handle-2", Expires, []));

        var result = await Service(_twoFactor.Object).LoginAsync(_user.UserName, "password");

        Assert.Equal(ResultCode.Accepted, result.Code);
        Assert.Empty(result.Meta.TwoFactorMethods);
        _issuer.Verify(i => i.IssueAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task NoEnrolledMethod_WithAllowBehavior_IssuesSessionAndResetsFailureCount() {
        _twoFactor.Setup(s => s.BeginAsync(_user, It.IsAny<CancellationToken>())).ReturnsAsync(TwoFactorLoginStart.SignIn());

        var result = await Service(_twoFactor.Object).LoginAsync(_user.UserName, "password");

        Assert.True(result.Succeeded);
        Assert.Equal("access-token", result.Meta.AuthenticationToken);
        _lockout.Verify(l => l.ResetAccessFailedCountAsync(_user), Times.Once);
    }

    [Fact]
    public async Task WithoutTwoFactorService_BehaviorIsUnchanged() {
        var result = await Service(null).LoginAsync(_user.UserName, "password");

        Assert.False(result.Succeeded);
        Assert.Equal(ResultCode.Accepted, result.Code);
        Assert.Null(result.Meta);
        _issuer.Verify(i => i.IssueAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task WrongPassword_NeverStartsTwoFactor() {
        _signIn.Setup(m => m.PasswordSignInAsync(_user, "wrong", false, true)).ReturnsAsync(SignInResult.Failed);

        var result = await Service(_twoFactor.Object).LoginAsync(_user.UserName, "wrong");

        Assert.Equal(ResultCode.BadRequest, result.Code);
        _twoFactor.Verify(s => s.BeginAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task UnconfirmedOrUnknownUser_NeverStartsTwoFactor() {
        _user.EmailConfirmed = false;

        var unconfirmed = await Service(_twoFactor.Object).LoginAsync(_user.UserName, "password");
        var unknown = await Service(_twoFactor.Object).LoginAsync("nobody", "password");

        Assert.Equal(ResultCode.BadRequest, unconfirmed.Code);
        Assert.Equal(ResultCode.BadRequest, unknown.Code);
        _twoFactor.Verify(s => s.BeginAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ChallengeStoreFailure_IsNotConvertedIntoASignIn() {
        _twoFactor.Setup(s => s.BeginAsync(_user, It.IsAny<CancellationToken>())).ThrowsAsync(new InvalidOperationException("db down"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => Service(_twoFactor.Object).LoginAsync(_user.UserName, "password"));

        _issuer.Verify(i => i.IssueAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
