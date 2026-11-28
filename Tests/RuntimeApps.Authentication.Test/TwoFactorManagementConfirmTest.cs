using Microsoft.AspNetCore.Identity;
using Moq;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

public class TwoFactorManagementConfirmTest {
    [Fact]
    public async Task Confirm_WithCorrectCode_EnablesTwoFactorAndRecordsTheCode() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();

        var result = await h.Service.ConfirmSetupAsync(h.User, "authenticator", "123456", h.Token);

        Assert.True(result.Succeeded);
        Assert.True(result.Data.Enabled);
        Assert.True(h.Enabled);
        Assert.Equal(1, await h.LedgerCountAsync());
        h.VerifyFailureCounted(Times.Never());
    }

    [Theory]
    [InlineData("123 456")]
    [InlineData("123-456")]
    [InlineData(" 123456 ")]
    public async Task Confirm_AcceptsEquivalentFormsOfTheSameCode(string submitted) {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        h.Authenticator.NormalizeAsDigits = true;

        Assert.True((await h.Service.ConfirmSetupAsync(h.User, "authenticator", submitted, h.Token)).Succeeded);
    }

    [Fact]
    public async Task Confirm_WithWrongCode_IsRejected_CountsTowardLockout_AndEnablesNothing() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();

        var result = await h.Service.ConfirmSetupAsync(h.User, "authenticator", "000000", h.Token);

        Assert.Equal(ResultCode.BadRequest, result.Code);
        Assert.Equal("InvalidCode", result.Errors.Single().Code);
        Assert.False(h.Enabled);
        h.VerifyFailureCounted(Times.Once());
        Assert.Equal(0, await h.LedgerCountAsync());
        Assert.Equal(0, h.Other.ClearCalls);
    }

    [Fact]
    public async Task Confirm_ACodeAlreadyAccepted_CannotBeReplayed() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        Assert.True((await h.Service.ConfirmSetupAsync(h.User, "authenticator", "123456", h.Token)).Succeeded);
        // Start over the way a user would: turn two-factor off outside this service, then try the same code again.
        h.Enabled = false;

        var replay = await h.Service.ConfirmSetupAsync(h.User, "authenticator", "123456", h.Token);

        Assert.Equal(ResultCode.BadRequest, replay.Code);
        Assert.False(h.Enabled);
        h.VerifyFailureCounted(Times.Once());
    }

    [Fact]
    public async Task Confirm_WhenAlreadyEnabled_IsConflict_WithoutVerifyingTheCode() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        h.Enabled = true;

        var result = await h.Service.ConfirmSetupAsync(h.User, "authenticator", "123456", h.Token);

        Assert.Equal(ResultCode.Conflict, result.Code);
        Assert.Equal(0, h.Authenticator.ConfirmCalls);
        Assert.Equal(0, await h.LedgerCountAsync());
    }

    [Fact]
    public async Task Confirm_ForALockedOutAccount_IsRejectedBeforeAnyCodeCheck() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        h.LockedOut = true;

        var result = await h.Service.ConfirmSetupAsync(h.User, "authenticator", "123456", h.Token);

        Assert.Equal(ResultCode.Locked, result.Code);
        Assert.Equal(0, h.Authenticator.ConfirmCalls);
        Assert.False(h.Enabled);
    }

    [Theory]
    [InlineData("nope")]
    [InlineData("")]
    [InlineData(null)]
    public async Task Confirm_UnknownMethod_IsBadRequest(string method) {
        await using var h = await TwoFactorManagementHarness.CreateAsync();

        var result = await h.Service.ConfirmSetupAsync(h.User, method, "123456", h.Token);

        Assert.Equal(ResultCode.BadRequest, result.Code);
        Assert.Equal("InvalidTwoFactorMethod", result.Errors.Single().Code);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("a-code-that-is-way-too-long-to-ever-be-valid-123456789")]
    public async Task Confirm_MalformedCode_IsRejectedWithoutCallingTheMethod(string code) {
        await using var h = await TwoFactorManagementHarness.CreateAsync();

        var result = await h.Service.ConfirmSetupAsync(h.User, "authenticator", code, h.Token);

        Assert.Equal(ResultCode.BadRequest, result.Code);
        Assert.Equal(0, h.Authenticator.ConfirmCalls);
        Assert.False(h.Enabled);
    }

    [Fact]
    public async Task Confirm_ClearsEveryOtherMethodBeforeEnabling_SoLeftoversCannotCountAsEnrolled() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        var order = new List<string>();
        h.Other.OnClear = () => order.Add("clear-other");
        h.TwoFactor.Setup(t => t.SetTwoFactorEnabledAsync(It.IsAny<IdentityUser<int>>(), true))
            .Callback(() => order.Add("enable")).ReturnsAsync(IdentityResult.Success);

        await h.Service.ConfirmSetupAsync(h.User, "authenticator", "123456", h.Token);

        Assert.Equal(["clear-other", "enable"], order);
        Assert.Equal(1, h.Other.ClearCalls);
        Assert.Equal(0, h.Authenticator.ClearCalls); // the confirmed method keeps what it just set up
    }

    [Fact]
    public async Task Confirm_WhenClearingFails_TwoFactorStaysOff() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        h.Other.OnClear = () => throw new InvalidOperationException("clear failed");

        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.ConfirmSetupAsync(h.User, "authenticator", "123456", h.Token));

        Assert.False(h.Enabled);
    }

    [Fact]
    public async Task Confirm_WhenTheFlagCannotBeSet_ThrowsInsteadOfReportingSuccess() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        h.TwoFactor.Setup(t => t.SetTwoFactorEnabledAsync(It.IsAny<IdentityUser<int>>(), true)).ReturnsAsync(IdentityResult.Failed());

        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.ConfirmSetupAsync(h.User, "authenticator", "123456", h.Token));
    }

    [Fact]
    public async Task Confirm_FailureBodies_NeverContainTheCode() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();

        var result = await h.Service.ConfirmSetupAsync(h.User, "authenticator", "987654", h.Token);

        Assert.DoesNotContain("987654", System.Text.Json.JsonSerializer.Serialize(result));
    }

    [Fact]
    public async Task Confirm_CancelledToken_ThrowsAndChangesNothing() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Service.ConfirmSetupAsync(h.User, "authenticator", "123456", cts.Token));

        Assert.False(h.Enabled);
        Assert.Equal(0, await h.LedgerCountAsync());
    }
}
