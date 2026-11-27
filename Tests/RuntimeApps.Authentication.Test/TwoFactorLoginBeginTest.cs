using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.TwoFactor.Services;
using RuntimeApps.Authentication.Features.Verification.Services;

namespace RuntimeApps.Authentication.Test;

public class TwoFactorLoginBeginTest {
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 9, 0, 0, TimeSpan.Zero);
    private static readonly IdentityUser<int> User = new() { Id = 7, UserName = "alice" };

    private sealed class Context {
        public Mock<ITwoFactorChallengeStore<int>> Store { get; } = new();
        public List<TwoFactorChallenge<int>> Created { get; } = [];
        public List<int> Caps { get; } = [];
        public TwoFactorOptions Options { get; } = new() { Issuer = "Acme" };

        public Context() => Store.Setup(s => s.CreateAsync(It.IsAny<TwoFactorChallenge<int>>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .Callback<TwoFactorChallenge<int>, int, CancellationToken>((c, cap, _) => { Created.Add(c); Caps.Add(cap); })
            .Returns(Task.CompletedTask);

        public TwoFactorLoginService<IdentityUser<int>, int> Service(params FakeTwoFactorMethod[] methods) =>
            new(Store.Object, methods, Microsoft.Extensions.Options.Options.Create(Options), new TestClock(Now));
    }

    [Fact]
    public async Task Begin_StoresOnlyTheHashOfTheHandleAndReturnsTheHandle() {
        var context = new Context();

        var start = await context.Service(new FakeTwoFactorMethod("authenticator")).BeginAsync(User, TestContext.Current.CancellationToken);

        var stored = Assert.Single(context.Created);
        Assert.False(start.SignInAllowed);
        Assert.Equal(VerificationHandle.ComputeHash(start.Challenge), stored.HandleHash);
        Assert.NotEqual(start.Challenge, stored.HandleHash);
        Assert.Equal(7, stored.UserId);
        Assert.Equal(TwoFactorChallengeStatus.Pending, stored.Status);
        Assert.Equal(Now, stored.CreatedAt);
        Assert.Equal(Now + TimeSpan.FromMinutes(5), stored.ExpiresAt);
        Assert.Equal(stored.ExpiresAt, start.ExpiresAt);
        Assert.Equal(5, Assert.Single(context.Caps));
    }

    [Fact]
    public async Task Begin_UsesConfiguredLifetimeAndPendingCap() {
        var context = new Context();
        context.Options.ChallengeLifetime = TimeSpan.FromMinutes(2);
        context.Options.MaxPendingChallengesPerUser = 3;

        await context.Service(new FakeTwoFactorMethod("authenticator")).BeginAsync(User, TestContext.Current.CancellationToken);

        Assert.Equal(Now + TimeSpan.FromMinutes(2), context.Created.Single().ExpiresAt);
        Assert.Equal(3, context.Caps.Single());
    }

    [Fact]
    public async Task Begin_ListsOnlyEnrolledMethodsWithDeliveryFlag() {
        var context = new Context();
        var authenticator = new FakeTwoFactorMethod("authenticator");
        var sms = new FakeTwoFactorMethod("sms", deliveryBased: true);
        var email = new FakeTwoFactorMethod("email", deliveryBased: true) { Enrolled = false };

        var start = await context.Service(authenticator, sms, email).BeginAsync(User, TestContext.Current.CancellationToken);

        Assert.Equal(new[] { new TwoFactorMethodInfo("authenticator", false), new TwoFactorMethodInfo("sms", true) }, start.Methods);
    }

    [Fact]
    public async Task Begin_NoEnrolledMethod_DefaultIsFailClosedWithEmptyMethodList() {
        var context = new Context();

        var start = await context.Service(new FakeTwoFactorMethod("authenticator") { Enrolled = false })
            .BeginAsync(User, TestContext.Current.CancellationToken);

        Assert.False(start.SignInAllowed);
        Assert.NotNull(start.Challenge);
        Assert.Empty(start.Methods);
        Assert.Single(context.Created);
    }

    [Fact]
    public async Task Begin_NoEnrolledMethod_AllowSignInOptIn_SkipsTheChallenge() {
        var context = new Context();
        context.Options.NoEnrolledMethodBehavior = TwoFactorNoMethodBehavior.AllowSignIn;

        var start = await context.Service(new FakeTwoFactorMethod("authenticator") { Enrolled = false })
            .BeginAsync(User, TestContext.Current.CancellationToken);

        Assert.True(start.SignInAllowed);
        Assert.Null(start.Challenge);
        context.Store.Verify(s => s.CreateAsync(It.IsAny<TwoFactorChallenge<int>>(), It.IsAny<int>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Begin_AllowSignInDoesNotApplyWhenAMethodIsEnrolled() {
        var context = new Context();
        context.Options.NoEnrolledMethodBehavior = TwoFactorNoMethodBehavior.AllowSignIn;

        var start = await context.Service(new FakeTwoFactorMethod("authenticator")).BeginAsync(User, TestContext.Current.CancellationToken);

        Assert.False(start.SignInAllowed);
        Assert.NotNull(start.Challenge);
    }

    [Fact]
    public async Task Begin_NoMethodsRegisteredAtAll_IsAlsoFailClosedByDefault() {
        var context = new Context();

        var start = await context.Service().BeginAsync(User, TestContext.Current.CancellationToken);

        Assert.False(start.SignInAllowed);
        Assert.Empty(start.Methods);
    }

    [Fact]
    public async Task Begin_GeneratesAFreshUnguessableHandleEachTime() {
        var context = new Context();
        var service = context.Service(new FakeTwoFactorMethod("authenticator"));

        var first = await service.BeginAsync(User, TestContext.Current.CancellationToken);
        var second = await service.BeginAsync(User, TestContext.Current.CancellationToken);

        Assert.NotEqual(first.Challenge, second.Challenge);
        Assert.True(first.Challenge.Length >= 40);
    }

    [Fact]
    public async Task Begin_CancelledToken_ThrowsWithoutTouchingTheStore() {
        var context = new Context();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => context.Service(new FakeTwoFactorMethod("authenticator")).BeginAsync(User, cts.Token));

        context.Store.Verify(s => s.CreateAsync(It.IsAny<TwoFactorChallenge<int>>(), It.IsAny<int>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Begin_NullUser_Throws() =>
        await Assert.ThrowsAsync<ArgumentNullException>(() => new Context().Service().BeginAsync(null, TestContext.Current.CancellationToken));

    [Fact]
    public async Task Begin_StoreFailureIsNotSwallowed() {
        var context = new Context();
        context.Store.Setup(s => s.CreateAsync(It.IsAny<TwoFactorChallenge<int>>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("database down"));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            context.Service(new FakeTwoFactorMethod("authenticator")).BeginAsync(User, TestContext.Current.CancellationToken));
    }
}
