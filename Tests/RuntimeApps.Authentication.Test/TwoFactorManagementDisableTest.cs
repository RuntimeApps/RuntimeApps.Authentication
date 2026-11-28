using Microsoft.AspNetCore.Identity;
using Moq;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

public class TwoFactorManagementDisableTest {
    private static TwoFactorDisableModel Request(string method = "authenticator", string code = "123456") =>
        new() { CurrentPassword = "password", Method = method, Code = code };

    private static async Task<TwoFactorManagementHarness> EnabledAsync() {
        var h = await TwoFactorManagementHarness.CreateAsync();
        h.Enabled = true;
        h.Authenticator.Enrolled = true;
        return h;
    }

    [Fact]
    public async Task Disable_WithProofAndCurrentCode_TurnsTwoFactorOffAndClearsEveryMethod() {
        await using var h = await EnabledAsync();

        var result = await h.Service.DisableAsync(h.User, Request(), h.Token);

        Assert.True(result.Succeeded);
        Assert.False(result.Data.Enabled);
        Assert.False(h.Enabled);
        Assert.Equal(1, h.Authenticator.ClearCalls);
        Assert.Equal(1, h.Other.ClearCalls);
        Assert.Equal(1, await h.LedgerCountAsync());
    }

    [Fact]
    public async Task Disable_WithoutFreshProof_IsForbidden_AndTheCodeIsNeverChecked() {
        await using var h = await EnabledAsync();
        h.Reauthenticated = false;

        var result = await h.Service.DisableAsync(h.User, Request(), h.Token);

        Assert.Equal(ResultCode.Forbidden, result.Code);
        Assert.Equal("ReauthenticationRequired", result.Errors.Single().Code);
        Assert.True(h.Enabled);
        Assert.Equal(0, h.Authenticator.VerifyCalls);
        Assert.Equal(0, h.Authenticator.ClearCalls);
    }

    [Fact]
    public async Task Disable_WithWrongCode_IsForbidden_CountsTowardLockout_AndChangesNothing() {
        await using var h = await EnabledAsync();

        var result = await h.Service.DisableAsync(h.User, Request(code: "000000"), h.Token);

        Assert.Equal(ResultCode.Forbidden, result.Code);
        Assert.Equal("InvalidCode", result.Errors.Single().Code);
        Assert.True(h.Enabled);
        h.VerifyFailureCounted(Times.Once());
        Assert.Equal(0, h.Authenticator.ClearCalls);
        Assert.Equal(0, await h.LedgerCountAsync());
    }

    [Fact]
    public async Task Disable_ACodeAlreadyUsedForLogin_CannotBeReplayed() {
        await using var h = await EnabledAsync();
        Assert.True(await h.Store.TryMarkCodeUsedAsync(h.User.Id, "authenticator",
            RuntimeApps.Authentication.Features.TwoFactor.Services.TwoFactorCodeHash.Compute("7", "authenticator", "123456"),
            h.Clock.Now, h.Clock.Now.AddMinutes(10), h.Token));

        var result = await h.Service.DisableAsync(h.User, Request(), h.Token);

        Assert.Equal(ResultCode.Forbidden, result.Code);
        Assert.True(h.Enabled);
        h.VerifyFailureCounted(Times.Once());
    }

    [Fact]
    public async Task Disable_UsingAMethodTheUserHasNotEnrolled_IsForbidden_WithoutVerifying() {
        await using var h = await EnabledAsync();

        var result = await h.Service.DisableAsync(h.User, Request(method: "sms", code: "654321"), h.Token);

        Assert.Equal(ResultCode.Forbidden, result.Code);
        Assert.Equal(0, h.Other.VerifyCalls);
        Assert.True(h.Enabled);
    }

    [Fact]
    public async Task Disable_WhenTwoFactorIsOff_IsConflict() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();

        var result = await h.Service.DisableAsync(h.User, Request(), h.Token);

        Assert.Equal(ResultCode.Conflict, result.Code);
        Assert.Equal("TwoFactorNotEnabled", result.Errors.Single().Code);
        Assert.Equal(0, h.Authenticator.VerifyCalls);
    }

    [Fact]
    public async Task Disable_ForALockedOutAccount_IsRejectedBeforeAnyCheck() {
        await using var h = await EnabledAsync();
        h.LockedOut = true;

        var result = await h.Service.DisableAsync(h.User, Request(), h.Token);

        Assert.Equal(ResultCode.Locked, result.Code);
        Assert.Equal(0, h.Authenticator.VerifyCalls);
        h.Reauthenticator.Verify(r => r.IsReauthenticatedAsync(It.IsAny<IdentityUser<int>>(), It.IsAny<TwoFactorReauthenticationModel>(), It.IsAny<CancellationToken>()), Times.Never);
        Assert.True(h.Enabled);
    }

    [Theory]
    [InlineData("nope")]
    [InlineData("")]
    [InlineData(null)]
    public async Task Disable_UnknownMethod_IsBadRequest_BeforeAnyPasswordIsChecked(string method) {
        await using var h = await EnabledAsync();

        var result = await h.Service.DisableAsync(h.User, Request(method: method), h.Token);

        Assert.Equal(ResultCode.BadRequest, result.Code);
        h.Reauthenticator.Verify(r => r.IsReauthenticatedAsync(It.IsAny<IdentityUser<int>>(), It.IsAny<TwoFactorReauthenticationModel>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Disable_NullRequest_IsBadRequest() {
        await using var h = await EnabledAsync();

        Assert.Equal(ResultCode.BadRequest, (await h.Service.DisableAsync(h.User, null, h.Token)).Code);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public async Task Disable_BlankCode_IsForbidden_WithoutCallingTheMethod(string code) {
        await using var h = await EnabledAsync();

        var result = await h.Service.DisableAsync(h.User, Request(code: code), h.Token);

        Assert.Equal(ResultCode.Forbidden, result.Code);
        Assert.Equal(0, h.Authenticator.VerifyCalls);
        Assert.True(h.Enabled);
    }

    [Fact]
    public async Task Disable_TurnsTheFlagOffBeforeClearing_SoAFailedClearNeverLeavesAnOrphanSecretWithTheFlagOn() {
        await using var h = await EnabledAsync();
        var order = new List<string>();
        h.TwoFactor.Setup(t => t.SetTwoFactorEnabledAsync(It.IsAny<IdentityUser<int>>(), false))
            .Callback(() => order.Add("disable")).ReturnsAsync(IdentityResult.Success);
        h.Authenticator.OnClear = () => order.Add("clear");

        await h.Service.DisableAsync(h.User, Request(), h.Token);

        Assert.Equal(["disable", "clear"], order);
    }

    [Fact]
    public async Task Disable_WhenClearingFails_TheFailureIsNotHidden_AndTwoFactorIsAlreadyOff() {
        await using var h = await EnabledAsync();
        h.Authenticator.OnClear = () => throw new InvalidOperationException("key store down");

        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.DisableAsync(h.User, Request(), h.Token));

        Assert.False(h.Enabled);
    }

    [Fact]
    public async Task Disable_WhenTheFlagCannotBeCleared_ThrowsAndClearsNothing() {
        await using var h = await EnabledAsync();
        h.TwoFactor.Setup(t => t.SetTwoFactorEnabledAsync(It.IsAny<IdentityUser<int>>(), false)).ReturnsAsync(IdentityResult.Failed());

        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.DisableAsync(h.User, Request(), h.Token));

        Assert.Equal(0, h.Authenticator.ClearCalls);
    }

    [Fact]
    public async Task Disable_FailureBodies_NeverContainTheCodeOrPassword() {
        await using var h = await EnabledAsync();

        var result = await h.Service.DisableAsync(h.User, Request(code: "987654"), h.Token);

        var text = System.Text.Json.JsonSerializer.Serialize(result);
        Assert.DoesNotContain("987654", text);
        Assert.DoesNotContain("password", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Disable_CancelledToken_ThrowsAndChangesNothing() {
        await using var h = await EnabledAsync();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Service.DisableAsync(h.User, Request(), cts.Token));

        Assert.True(h.Enabled);
        Assert.Equal(0, await h.LedgerCountAsync());
    }

    [Fact]
    public async Task Setup_ForALockedOutAccount_IsRejectedBeforeAnyCheck() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        h.LockedOut = true;

        var result = await h.Service.BeginSetupAsync(h.User, "authenticator", new TwoFactorReauthenticationModel { CurrentPassword = "password" }, h.Token);

        Assert.Equal(ResultCode.Locked, result.Code);
        Assert.Equal(0, h.Authenticator.BeginCalls);
    }
}
