using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.Account.Services;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

/// <summary>How an external provider login hands over to the second step.</summary>
public class UserAccountServiceTwoFactorExternalLoginTest {
    private static readonly DateTimeOffset Expires = new(2026, 1, 1, 9, 5, 0, TimeSpan.Zero);

    private readonly IdentityUser _user = new() { UserName = "ext-user", Email = "ext@example.com", EmailConfirmed = true };
    private readonly Mock<IExternalLoginService<IdentityUser>> _external = new();
    private readonly Mock<IAuthenticationSessionIssuer<IdentityUser>> _issuer = new();
    private readonly Mock<ITwoFactorLoginService<IdentityUser>> _twoFactor = new();

    public UserAccountServiceTwoFactorExternalLoginTest() {
        _external.Setup(e => e.ResolveLoginAsync("Google", "token", It.IsAny<CancellationToken>())).ReturnsAsync(new Result<IdentityUser>(_user));
        _issuer.Setup(i => i.IssueAsync(_user, It.IsAny<CancellationToken>())).ReturnsAsync(new Token { AuthenticationToken = "access-token" });
    }

    private UserAccountService<IdentityUser, string> Service(ITwoFactorLoginService<IdentityUser> twoFactor, VerificationOptions verification = null,
        IVerificationWorkflowService<IdentityUser, string> workflow = null) =>
        new(Mock.Of<IUserManager<IdentityUser>>(), Mock.Of<ISignInManager<IdentityUser>>(), Array.Empty<IExternalLoginProvider<IdentityUser>>(),
            Mock.Of<IAuthenticationHandlerProvider>(), Mock.Of<IHttpContextAccessor>(),
            Mock.Of<IUserClaimsPrincipalFactory<IdentityUser>>(), Mock.Of<IAuthenticationSchemeProvider>(),
            verificationOptions: verification == null ? null : Options.Create(verification), verificationWorkflow: workflow,
            sessionIssuer: _issuer.Object, externalLoginService: _external.Object, twoFactorLogin: twoFactor);

    private void VerifyNoSession() =>
        _issuer.Verify(i => i.IssueAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never);

    [Fact]
    public async Task UserWithTwoFactor_GetsAChallengeAndNoSession() {
        // Also covers an existing account that the provider login was linked to by trusted email.
        IReadOnlyList<TwoFactorMethodInfo> methods = [new TwoFactorMethodInfo("authenticator", false)];
        _twoFactor.Setup(s => s.BeginExternalAsync(_user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(TwoFactorLoginStart.Required("handle-1", Expires, methods));

        var result = await Service(_twoFactor.Object).ExternalLoginAsync("Google", "token");

        Assert.False(result.Succeeded);
        Assert.Equal(ResultCode.Accepted, result.Code);
        Assert.Equal("handle-1", result.Meta.TwoFactorChallenge);
        Assert.Equal(Expires, result.Meta.TwoFactorExpiresAt);
        Assert.Equal("authenticator", Assert.Single(result.Meta.TwoFactorMethods).Name);
        Assert.Null(result.Meta.AuthenticationToken);
        VerifyNoSession();
    }

    [Fact]
    public async Task UserWithTwoFactor_WithoutEnrolledMethod_GetsAChallengeWithNoMethods() {
        _twoFactor.Setup(s => s.BeginExternalAsync(_user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(TwoFactorLoginStart.Required("handle-2", Expires, []));

        var result = await Service(_twoFactor.Object).ExternalLoginAsync("Google", "token");

        Assert.Equal(ResultCode.Accepted, result.Code);
        Assert.Empty(result.Meta.TwoFactorMethods);
        VerifyNoSession();
    }

    [Fact]
    public async Task WhenTheServiceAllowsSignIn_SessionIsIssued() {
        _twoFactor.Setup(s => s.BeginExternalAsync(_user, It.IsAny<CancellationToken>())).ReturnsAsync(TwoFactorLoginStart.SignIn());

        var result = await Service(_twoFactor.Object).ExternalLoginAsync("Google", "token");

        Assert.True(result.Succeeded);
        Assert.Equal("access-token", result.Meta.AuthenticationToken);
    }

    [Fact]
    public async Task WithoutTwoFactorService_BehaviorIsUnchanged() {
        var result = await Service(null).ExternalLoginAsync("Google", "token");

        Assert.True(result.Succeeded);
        Assert.Equal("access-token", result.Meta.AuthenticationToken);
    }

    [Fact]
    public async Task ProviderFailure_NeverStartsTwoFactor() {
        _external.Setup(e => e.ResolveLoginAsync("Google", "bad", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<IdentityUser>(ResultCode.BadRequest, Result.CreateErrors("x", "y")));

        var result = await Service(_twoFactor.Object).ExternalLoginAsync("Google", "bad");

        Assert.False(result.Succeeded);
        Assert.NotEqual(ResultCode.Accepted, result.Code);
        _twoFactor.Verify(s => s.BeginExternalAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never);
        VerifyNoSession();
    }

    [Fact]
    public async Task EmailVerificationComesFirst_NoChallengeBeforeTheEmailIsConfirmed() {
        _user.EmailConfirmed = false;
        var workflow = new Mock<IVerificationWorkflowService<IdentityUser, string>>();
        workflow.Setup(w => w.StartAsync(_user, VerificationPurpose.Registration, VerificationChannel.Email, _user.Email, null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(VerificationOperationResult.Success("verification-handle", Expires));

        var result = await Service(_twoFactor.Object, new VerificationOptions { RequireEmailVerificationForExternalLogins = true }, workflow.Object)
            .ExternalLoginAsync("Google", "token");

        Assert.True(result.Meta.VerificationRequired);
        Assert.Null(result.Meta.TwoFactorChallenge);
        _twoFactor.Verify(s => s.BeginExternalAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never);
        VerifyNoSession();
    }

    [Fact]
    public async Task ChallengeStoreFailure_IsNotConvertedIntoASignIn() {
        _twoFactor.Setup(s => s.BeginExternalAsync(_user, It.IsAny<CancellationToken>())).ThrowsAsync(new InvalidOperationException("db down"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => Service(_twoFactor.Object).ExternalLoginAsync("Google", "token"));

        VerifyNoSession();
    }
}
