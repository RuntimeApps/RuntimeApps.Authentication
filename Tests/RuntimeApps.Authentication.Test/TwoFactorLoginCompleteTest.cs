using Microsoft.AspNetCore.Identity;
using Moq;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

/// <summary>Security-focused behavior of completing a login with a second factor.</summary>
public class TwoFactorLoginCompleteTest {
    // ---- success ----

    [Fact]
    public async Task ValidCode_IssuesSessionConsumesChallengeAndRecordsCode() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();

        var result = await h.CompleteAsync(handle);

        Assert.True(result.Succeeded);
        Assert.Same(h.User, result.Data);
        Assert.Equal("access-token", result.Meta.AuthenticationToken);
        h.Issuer.Verify(i => i.IssueAsync(h.User, It.IsAny<CancellationToken>()), Times.Once);
        Assert.Equal(TwoFactorChallengeStatus.Completed, (await h.StoredChallengeAsync(handle)).Status);
        Assert.Equal(1, await h.LedgerCountAsync());
        h.Lockout.Verify(l => l.ResetAccessFailedCountAsync(h.User), Times.Once);
        h.VerifyFailureCounted(Times.Never());
    }

    [Fact]
    public async Task MethodNameIsMatchedCaseInsensitively() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();

        var result = await h.CompleteAsync(await h.StartChallengeAsync(), method: "Authenticator");

        Assert.True(result.Succeeded);
    }

    // ---- wrong codes and attempt limits ----

    [Fact]
    public async Task WrongCode_IsRejected_CountsTowardLockout_AndAllowsRetryOnSameChallenge() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();

        var wrong = await h.CompleteAsync(handle, "000000");

        Assert.False(wrong.Succeeded);
        h.VerifyNoSessionWasIssued();
        h.VerifyFailureCounted(Times.Once());
        var stored = await h.StoredChallengeAsync(handle);
        Assert.Equal(1, stored.Attempts);
        Assert.Equal(TwoFactorChallengeStatus.Pending, stored.Status);
        Assert.Equal(0, await h.LedgerCountAsync());
        Assert.True((await h.CompleteAsync(handle)).Succeeded);
    }

    [Fact]
    public async Task AttemptLimit_StopsTheChallengeEvenForTheCorrectCode() {
        await using var h = await TwoFactorLoginHarness.CreateAsync(o => o.MaxAttemptsPerChallenge = 3);
        var handle = await h.StartChallengeAsync();

        for(var i = 0; i < 3; i++)
            Assert.False((await h.CompleteAsync(handle, "000000")).Succeeded);
        var correct = await h.CompleteAsync(handle);

        Assert.False(correct.Succeeded);
        h.VerifyNoSessionWasIssued();
        Assert.Equal(3, h.Authenticator.VerifyCalls); // the fourth attempt never reached the method
    }

    [Fact]
    public async Task AttemptLimit_IsConfigurable_AndLastAttemptMayStillSucceed() {
        await using var h = await TwoFactorLoginHarness.CreateAsync(o => o.MaxAttemptsPerChallenge = 2);
        var handle = await h.StartChallengeAsync();

        Assert.False((await h.CompleteAsync(handle, "000000")).Succeeded);

        Assert.True((await h.CompleteAsync(handle)).Succeeded);
    }

    // ---- single use and replay ----

    [Fact]
    public async Task ChallengeCanBeCompletedOnlyOnce() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();
        Assert.True((await h.CompleteAsync(handle)).Succeeded);

        var again = await h.CompleteAsync(handle);

        Assert.False(again.Succeeded);
        h.Issuer.Verify(i => i.IssueAsync(It.IsAny<IdentityUser<int>>(), It.IsAny<CancellationToken>()), Times.Once);
        Assert.Equal(1, h.Authenticator.VerifyCalls);
    }

    [Theory]
    [InlineData("123456")]
    [InlineData("123 456")]
    [InlineData(" 123456 ")]
    public async Task AcceptedCode_CannotBeReplayedOnANewChallenge(string replayedForm) {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        Assert.True((await h.CompleteAsync(await h.StartChallengeAsync())).Succeeded);
        var second = await h.StartChallengeAsync();

        var replay = await h.CompleteAsync(second, replayedForm);

        Assert.False(replay.Succeeded);
        h.Issuer.Verify(i => i.IssueAsync(It.IsAny<IdentityUser<int>>(), It.IsAny<CancellationToken>()), Times.Once);
        h.VerifyFailureCounted(Times.Once());
        Assert.Equal(TwoFactorChallengeStatus.Pending, (await h.StoredChallengeAsync(second)).Status);
    }

    [Fact]
    public async Task AcceptedCode_IsAcceptedAgainOnceTheRetentionWindowPassed() {
        await using var h = await TwoFactorLoginHarness.CreateAsync(o => o.UsedCodeRetention = TimeSpan.FromMinutes(3));
        Assert.True((await h.CompleteAsync(await h.StartChallengeAsync())).Succeeded);
        h.Clock.Advance(TimeSpan.FromMinutes(4));

        Assert.True((await h.CompleteAsync(await h.StartChallengeAsync())).Succeeded);
    }

    // ---- unknown, expired, superseded challenges ----

    [Fact]
    public async Task UnknownChallenge_IsRejectedWithoutReachingTheMethod() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        await h.StartChallengeAsync();

        var result = await h.CompleteAsync("not-a-real-handle");

        Assert.False(result.Succeeded);
        Assert.Equal(0, h.Authenticator.VerifyCalls);
        h.VerifyNoSessionWasIssued();
    }

    [Fact]
    public async Task ExpiredChallenge_IsRejectedEvenWithTheCorrectCode() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();
        h.Clock.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));

        var result = await h.CompleteAsync(handle);

        Assert.False(result.Succeeded);
        Assert.Equal(0, h.Authenticator.VerifyCalls);
        h.VerifyNoSessionWasIssued();
    }

    [Fact]
    public async Task SupersededChallenge_IsRejected() {
        await using var h = await TwoFactorLoginHarness.CreateAsync(o => o.MaxPendingChallengesPerUser = 1);
        var first = await h.StartChallengeAsync();
        h.Clock.Advance(TimeSpan.FromSeconds(1));
        var second = await h.StartChallengeAsync();

        Assert.False((await h.CompleteAsync(first)).Succeeded);
        Assert.True((await h.CompleteAsync(second)).Succeeded);
    }

    // ---- method problems ----

    [Fact]
    public async Task UnknownMethod_IsRejected_AndSpendsAnAttempt() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();

        var result = await h.CompleteAsync(handle, method: "sms");

        Assert.False(result.Succeeded);
        Assert.Equal(0, h.Authenticator.VerifyCalls);
        Assert.Equal(1, (await h.StoredChallengeAsync(handle)).Attempts);
        h.VerifyNoSessionWasIssued();
    }

    [Fact]
    public async Task MethodNotEnrolledForTheUser_IsRejected() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();
        h.Authenticator.Enrolled = false;

        var result = await h.CompleteAsync(handle);

        Assert.False(result.Succeeded);
        Assert.Equal(0, h.Authenticator.VerifyCalls);
        h.VerifyNoSessionWasIssued();
    }

    [Fact]
    public async Task MalformedCodeForTheMethod_IsRejectedWithoutCallingVerify() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();

        Assert.False((await h.CompleteAsync(handle, new string('1', 33))).Succeeded);

        Assert.Equal(0, h.Authenticator.VerifyCalls);
    }

    // ---- account state ----

    [Fact]
    public async Task LockedOutUser_IsRejectedWithoutVerifyingTheCode() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();
        h.LockedOut = true;

        var result = await h.CompleteAsync(handle);

        Assert.False(result.Succeeded);
        Assert.Equal(0, h.Authenticator.VerifyCalls);
        h.VerifyNoSessionWasIssued();
    }

    [Fact]
    public async Task UserWhoLostEligibilityAfterTheFirstStep_IsRejected() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();
        h.User.EmailConfirmed = false;

        Assert.False((await h.CompleteAsync(handle)).Succeeded);

        h.VerifyNoSessionWasIssued();
    }

    [Fact]
    public async Task DeletedUser_IsRejected() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();
        h.UserExists = false;

        Assert.False((await h.CompleteAsync(handle)).Succeeded);

        h.VerifyNoSessionWasIssued();
    }

    // ---- input validation ----

    [Theory]
    [InlineData(null, "authenticator", "123456")]
    [InlineData("", "authenticator", "123456")]
    [InlineData("handle", null, "123456")]
    [InlineData("handle", "  ", "123456")]
    [InlineData("handle", "authenticator", null)]
    [InlineData("handle", "authenticator", "")]
    public async Task BlankInput_IsRejectedBeforeAnyStoreAccess(string challenge, string method, string code) {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var real = await h.StartChallengeAsync();

        var result = await h.Service.CompleteAsync(challenge ?? string.Empty, method, code, h.Token);

        Assert.False(result.Succeeded);
        Assert.Equal(0, (await h.StoredChallengeAsync(real)).Attempts);
    }

    [Fact]
    public async Task OversizedInput_IsRejectedBeforeAnyStoreAccess() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();

        Assert.False((await h.Service.CompleteAsync(new string('a', 257), "authenticator", "123456", h.Token)).Succeeded);
        Assert.False((await h.Service.CompleteAsync(handle, new string('a', 33), "123456", h.Token)).Succeeded);
        Assert.False((await h.Service.CompleteAsync(handle, "authenticator", new string('1', 65), h.Token)).Succeeded);

        Assert.Equal(0, (await h.StoredChallengeAsync(handle)).Attempts);
    }

    // ---- uniform failures, errors, cancellation ----

    [Fact]
    public async Task AllFailureReasons_ProduceTheSameResult() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();
        var failures = new List<Result<IdentityUser<int>, Token>> {
            await h.CompleteAsync("unknown-handle"),
            await h.CompleteAsync(handle, "000000"),
            await h.CompleteAsync(handle, method: "sms"),
            await h.CompleteAsync(handle, " "),
        };

        Assert.All(failures, failure => {
            Assert.False(failure.Succeeded);
            Assert.Equal(failures[0].Code, failure.Code);
            Assert.Null(failure.Data);
            Assert.Null(failure.Meta);
            Assert.Equal(failures[0].Errors.Single().Code, failure.Errors.Single().Code);
            Assert.Equal(failures[0].Errors.Single().Description, failure.Errors.Single().Description);
        });
    }

    [Fact]
    public async Task FailedResults_NeverContainTheChallengeOrCode() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();

        var result = await h.CompleteAsync(handle, "987654");

        var text = System.Text.Json.JsonSerializer.Serialize(result);
        Assert.DoesNotContain(handle, text);
        Assert.DoesNotContain("987654", text);
    }

    [Fact]
    public async Task MethodFailure_IsNotReportedAsAWrongCode() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();
        h.Authenticator.VerifyException = new InvalidOperationException("provider unavailable");

        await Assert.ThrowsAsync<InvalidOperationException>(() => h.CompleteAsync(handle));

        h.VerifyNoSessionWasIssued();
        h.VerifyFailureCounted(Times.Never());
    }

    [Fact]
    public async Task CancelledToken_ThrowsAndConsumesNothing() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Service.CompleteAsync(handle, "authenticator", "123456", cts.Token));

        var stored = await h.StoredChallengeAsync(handle);
        Assert.Equal(0, stored.Attempts);
        Assert.Equal(TwoFactorChallengeStatus.Pending, stored.Status);
        h.VerifyNoSessionWasIssued();
    }

    [Fact]
    public async Task OnlyTheHandleHolderCanCompleteTheChallenge_AnotherUsersChallengeIsNotGuessable() {
        await using var h = await TwoFactorLoginHarness.CreateAsync();
        var handle = await h.StartChallengeAsync();
        var guessed = handle[..^1] + (handle[^1] == 'A' ? 'B' : 'A');

        Assert.False((await h.CompleteAsync(guessed)).Succeeded);

        Assert.Equal(0, h.Authenticator.VerifyCalls);
    }
}
