using Microsoft.AspNetCore.Identity;
using Moq;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.TwoFactor.Services;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.Test;

/// <summary>Re-authentication for two-factor setup changes.</summary>
public class TwoFactorReauthenticatorTest {
    private readonly IdentityUser _user = new() { UserName = "alice" };
    private readonly Mock<IUserLockoutManager<IdentityUser>> _lockout = new();
    private readonly Mock<IUserPasswordManager<IdentityUser>> _passwords = new();
    private readonly Mock<ISignInManager<IdentityUser>> _signIn = new();
    private readonly Mock<IUserLoginManager<IdentityUser>> _logins = new();
    private readonly Mock<IExternalLoginProvider<IdentityUser>> _provider = new();

    public TwoFactorReauthenticatorTest() {
        _passwords.Setup(p => p.HasPasswordAsync(_user)).ReturnsAsync(true);
        _signIn.Setup(s => s.CheckPasswordSignInAsync(_user, "right", true)).ReturnsAsync(SignInResult.Success);
        _signIn.Setup(s => s.CheckPasswordSignInAsync(_user, "wrong", true)).ReturnsAsync(SignInResult.Failed);
        _provider.SetupGet(p => p.Provider).Returns("Google");
        _provider.Setup(p => p.ValidateAsync("fresh", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ExternalLoginProviderResult<IdentityUser> { LoginInfo = new UserLoginInfo("Google", "subject-1", "Google") });
        _logins.Setup(l => l.GetLoginsAsync(_user)).ReturnsAsync(new List<UserLoginInfo> { new("Google", "subject-1", "Google") });
    }

    private TwoFactorReauthenticator<IdentityUser> Sut() =>
        new(_lockout.Object, _passwords.Object, _signIn.Object, _logins.Object, [_provider.Object]);

    private Task<bool> Check(TwoFactorReauthenticationModel request) =>
        Sut().IsReauthenticatedAsync(_user, request, TestContext.Current.CancellationToken);

    [Fact]
    public async Task CorrectPassword_Passes_AndFailuresAreCountedTowardLockout() {
        Assert.True(await Check(new() { CurrentPassword = "right" }));

        _signIn.Verify(s => s.CheckPasswordSignInAsync(_user, "right", true), Times.Once);
    }

    [Fact]
    public async Task WrongPassword_Fails_WithLockoutCountingOn() {
        Assert.False(await Check(new() { CurrentPassword = "wrong" }));

        _signIn.Verify(s => s.CheckPasswordSignInAsync(_user, "wrong", true), Times.Once);
    }

    [Fact]
    public async Task PasswordForAnAccountWithoutPassword_Fails_WithoutCheckingTheSignIn() {
        _passwords.Setup(p => p.HasPasswordAsync(_user)).ReturnsAsync(false);

        Assert.False(await Check(new() { CurrentPassword = "right" }));

        _signIn.Verify(s => s.CheckPasswordSignInAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<bool>()), Times.Never);
    }

    [Fact]
    public async Task LockedOutAccount_NeverPasses_AndNothingIsChecked() {
        _lockout.Setup(l => l.IsLockedOutAsync(_user)).ReturnsAsync(true);

        Assert.False(await Check(new() { CurrentPassword = "right" }));
        Assert.False(await Check(new() { ReauthenticationProvider = "Google", ReauthenticationToken = "fresh" }));

        _signIn.Verify(s => s.CheckPasswordSignInAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<bool>()), Times.Never);
        _provider.Verify(p => p.ValidateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task WrongPassword_DoesNotFallBackToAValidProviderToken() {
        Assert.False(await Check(new() { CurrentPassword = "wrong", ReauthenticationProvider = "Google", ReauthenticationToken = "fresh" }));

        _provider.Verify(p => p.ValidateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Theory]
    [InlineData("Google")]
    [InlineData("google")]
    public async Task FreshTokenOfALinkedIdentity_Passes(string providerName) {
        Assert.True(await Check(new() { ReauthenticationProvider = providerName, ReauthenticationToken = "fresh" }));
    }

    [Fact]
    public async Task FreshTokenOfADifferentIdentityOfTheSameProvider_Fails() {
        _logins.Setup(l => l.GetLoginsAsync(_user)).ReturnsAsync(new List<UserLoginInfo> { new("Google", "another-subject", "Google") });

        Assert.False(await Check(new() { ReauthenticationProvider = "Google", ReauthenticationToken = "fresh" }));
    }

    [Fact]
    public async Task ProviderKeyComparisonIsCaseSensitive() {
        _logins.Setup(l => l.GetLoginsAsync(_user)).ReturnsAsync(new List<UserLoginInfo> { new("Google", "SUBJECT-1", "Google") });

        Assert.False(await Check(new() { ReauthenticationProvider = "Google", ReauthenticationToken = "fresh" }));
    }

    [Fact]
    public async Task ProviderNotLinkedToTheAccount_Fails() {
        _logins.Setup(l => l.GetLoginsAsync(_user)).ReturnsAsync(new List<UserLoginInfo>());

        Assert.False(await Check(new() { ReauthenticationProvider = "Google", ReauthenticationToken = "fresh" }));
    }

    [Fact]
    public async Task UnknownProvider_InvalidToken_OrNoIdentity_Fail() {
        Assert.False(await Check(new() { ReauthenticationProvider = "Unknown", ReauthenticationToken = "fresh" }));
        Assert.False(await Check(new() { ReauthenticationProvider = "Google", ReauthenticationToken = "stale" }));
        _provider.Setup(p => p.ValidateAsync("no-login", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ExternalLoginProviderResult<IdentityUser>());
        Assert.False(await Check(new() { ReauthenticationProvider = "Google", ReauthenticationToken = "no-login" }));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("Google", null)]
    [InlineData(null, "fresh")]
    [InlineData(" ", " ")]
    public async Task IncompleteProviderProof_Fails(string provider, string token) {
        Assert.False(await Check(new() { ReauthenticationProvider = provider, ReauthenticationToken = token }));
    }

    [Fact]
    public async Task NoProofAtAll_Fails() {
        Assert.False(await Check(new()));
        Assert.False(await Check(null));
    }

    [Fact]
    public async Task CancelledToken_ThrowsBeforeAnyCheck() {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Sut().IsReauthenticatedAsync(_user, new() { CurrentPassword = "right" }, cts.Token));

        _signIn.Verify(s => s.CheckPasswordSignInAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<bool>()), Times.Never);
    }
}
