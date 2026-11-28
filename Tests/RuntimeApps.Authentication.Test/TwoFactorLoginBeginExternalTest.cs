using Microsoft.AspNetCore.Identity;
using Moq;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.TwoFactor.Services;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.Test;

/// <summary>Second-factor policy for users who signed in with an external provider.</summary>
public class TwoFactorLoginBeginExternalTest {
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 9, 0, 0, TimeSpan.Zero);
    private static readonly IdentityUser<int> User = new() { Id = 7, UserName = "alice" };

    private sealed class Context {
        public Mock<ITwoFactorChallengeStore<int>> Store { get; } = new();
        public Mock<IUserTwoFactorManager<IdentityUser<int>>> TwoFactor { get; } = new();
        public TwoFactorOptions Options { get; } = new() { Issuer = "Acme" };

        public Context(bool twoFactorEnabled = true) {
            TwoFactor.Setup(t => t.GetTwoFactorEnabledAsync(It.IsAny<IdentityUser<int>>())).ReturnsAsync(twoFactorEnabled);
            Store.Setup(s => s.CreateAsync(It.IsAny<TwoFactorChallenge<int>>(), It.IsAny<int>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        }

        public TwoFactorLoginService<IdentityUser<int>, int> Service(params FakeTwoFactorMethod[] methods) =>
            new(Store.Object, methods, Microsoft.Extensions.Options.Options.Create(Options), new TestClock(Now),
                Mock.Of<IUserManager<IdentityUser<int>>>(), Mock.Of<IUserLockoutManager<IdentityUser<int>>>(),
                new TwoFactorAccountEligibility<IdentityUser<int>, int>(
                    Mock.Of<IUserLockoutManager<IdentityUser<int>>>(), Mock.Of<IUserLoginManager<IdentityUser<int>>>(),
                    Mock.Of<ISignInManager<IdentityUser<int>>>(), Microsoft.Extensions.Options.Options.Create(new VerificationOptions())),
                Mock.Of<IAuthenticationSessionIssuer<IdentityUser<int>>>(), TwoFactor.Object);

        public void VerifyNoChallengeCreated() =>
            Store.Verify(s => s.CreateAsync(It.IsAny<TwoFactorChallenge<int>>(), It.IsAny<int>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task DefaultPolicy_UserWithTwoFactor_GetsAChallenge() {
        var context = new Context();

        var start = await context.Service(new FakeTwoFactorMethod("authenticator")).BeginExternalAsync(User, TestContext.Current.CancellationToken);

        Assert.False(start.SignInAllowed);
        Assert.False(string.IsNullOrEmpty(start.Challenge));
        Assert.Equal("authenticator", Assert.Single(start.Methods).Name);
        context.Store.Verify(s => s.CreateAsync(It.Is<TwoFactorChallenge<int>>(c => c.UserId == 7), It.IsAny<int>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task DefaultPolicy_UserWithoutTwoFactor_SignsInWithoutAChallenge() {
        var context = new Context(twoFactorEnabled: false);

        var start = await context.Service(new FakeTwoFactorMethod("authenticator")).BeginExternalAsync(User, TestContext.Current.CancellationToken);

        Assert.True(start.SignInAllowed);
        context.VerifyNoChallengeCreated();
    }

    [Fact]
    public async Task TrustProvider_UserWithTwoFactor_SignsInWithoutAChallenge() {
        var context = new Context();
        context.Options.ExternalLoginPolicy = TwoFactorExternalLoginPolicy.TrustProvider;

        var start = await context.Service(new FakeTwoFactorMethod("authenticator")).BeginExternalAsync(User, TestContext.Current.CancellationToken);

        Assert.True(start.SignInAllowed);
        context.VerifyNoChallengeCreated();
    }

    [Fact]
    public async Task DefaultPolicy_FlaggedUserWithoutEnrolledMethod_IsFailClosed() {
        var context = new Context();

        var start = await context.Service(new FakeTwoFactorMethod("authenticator") { Enrolled = false }).BeginExternalAsync(User, TestContext.Current.CancellationToken);

        Assert.False(start.SignInAllowed);
        Assert.Empty(start.Methods);
        Assert.False(string.IsNullOrEmpty(start.Challenge));
    }

    [Fact]
    public async Task DefaultPolicy_FlaggedUserWithoutEnrolledMethod_FollowsNoEnrolledMethodBehavior() {
        var context = new Context();
        context.Options.NoEnrolledMethodBehavior = TwoFactorNoMethodBehavior.AllowSignIn;

        var start = await context.Service(new FakeTwoFactorMethod("authenticator") { Enrolled = false }).BeginExternalAsync(User, TestContext.Current.CancellationToken);

        Assert.True(start.SignInAllowed);
    }

    [Fact]
    public async Task CancelledToken_Throws_AndCreatesNothing() {
        var context = new Context();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            context.Service(new FakeTwoFactorMethod("authenticator")).BeginExternalAsync(User, cts.Token));

        context.VerifyNoChallengeCreated();
    }

    [Fact]
    public async Task NullUser_Throws() {
        var context = new Context();

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            context.Service().BeginExternalAsync(null, TestContext.Current.CancellationToken));
    }
}
