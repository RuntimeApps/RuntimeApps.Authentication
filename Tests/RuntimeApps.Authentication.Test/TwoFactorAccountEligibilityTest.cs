using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.Features.TwoFactor.Services;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.Test;

public class TwoFactorAccountEligibilityTest {
    private sealed class Context {
        public Mock<IUserLockoutManager<IdentityUser<int>>> Lockout { get; } = new();
        public Mock<IUserLoginManager<IdentityUser<int>>> Logins { get; } = new();
        public Mock<ISignInManager<IdentityUser<int>>> SignIn { get; } = new();
        public VerificationOptions Verification { get; } = new();

        public Context() {
            Lockout.Setup(l => l.IsLockedOutAsync(It.IsAny<IdentityUser<int>>())).ReturnsAsync(false);
            Logins.Setup(l => l.GetLoginsAsync(It.IsAny<IdentityUser<int>>())).ReturnsAsync(new List<UserLoginInfo>());
            SignIn.Setup(s => s.CanSignInAsync(It.IsAny<IdentityUser<int>>())).ReturnsAsync(true);
        }

        public TwoFactorAccountEligibility<IdentityUser<int>, int> Create() =>
            new(Lockout.Object, Logins.Object, SignIn.Object, Options.Create(Verification));

        public void WithExternalLogin() => Logins.Setup(l => l.GetLoginsAsync(It.IsAny<IdentityUser<int>>()))
            .ReturnsAsync(new List<UserLoginInfo> { new("google", "key", "Google") });
    }

    private static IdentityUser<int> Confirmed() => new() { Id = 1, EmailConfirmed = true };
    private static IdentityUser<int> Unconfirmed() => new() { Id = 1, EmailConfirmed = false };

    [Fact]
    public async Task ConfirmedUnlockedUser_IsEligible() =>
        Assert.True(await new Context().Create().IsEligibleAsync(Confirmed(), TestContext.Current.CancellationToken));

    [Fact]
    public async Task NullUser_IsNotEligible() =>
        Assert.False(await new Context().Create().IsEligibleAsync(null, TestContext.Current.CancellationToken));

    [Fact]
    public async Task LockedOutUser_IsNotEligible_AndNothingElseIsConsulted() {
        var context = new Context();
        context.Lockout.Setup(l => l.IsLockedOutAsync(It.IsAny<IdentityUser<int>>())).ReturnsAsync(true);

        Assert.False(await context.Create().IsEligibleAsync(Confirmed(), TestContext.Current.CancellationToken));

        context.Logins.Verify(l => l.GetLoginsAsync(It.IsAny<IdentityUser<int>>()), Times.Never);
        context.SignIn.Verify(s => s.CanSignInAsync(It.IsAny<IdentityUser<int>>()), Times.Never);
    }

    [Fact]
    public async Task UnconfirmedUserWithoutExternalLogin_IsNotEligible() =>
        Assert.False(await new Context().Create().IsEligibleAsync(Unconfirmed(), TestContext.Current.CancellationToken));

    [Fact]
    public async Task UnconfirmedUserWithExternalLogin_IsEligibleUnlessVerificationIsRequired() {
        var context = new Context();
        context.WithExternalLogin();
        Assert.True(await context.Create().IsEligibleAsync(Unconfirmed(), TestContext.Current.CancellationToken));

        context.Verification.RequireEmailVerificationForExternalLogins = true;
        Assert.False(await context.Create().IsEligibleAsync(Unconfirmed(), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ConfirmedUserRejectedBySignInManager_IsNotEligible() {
        var context = new Context();
        context.SignIn.Setup(s => s.CanSignInAsync(It.IsAny<IdentityUser<int>>())).ReturnsAsync(false);

        Assert.False(await context.Create().IsEligibleAsync(Confirmed(), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CancelledToken_Throws() {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new Context().Create().IsEligibleAsync(Confirmed(), cts.Token));
    }
}
