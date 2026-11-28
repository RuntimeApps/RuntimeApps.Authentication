using Microsoft.AspNetCore.Identity;
using Moq;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

public class TwoFactorManagementSetupTest {
    private static readonly TwoFactorReauthenticationModel Proof = new() { CurrentPassword = "password" };

    [Fact]
    public async Task Setup_ReturnsEnrollmentData_WithoutEnablingTwoFactor() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();

        var result = await h.Service.BeginSetupAsync(h.User, "authenticator", Proof, h.Token);

        Assert.True(result.Succeeded);
        Assert.Equal("SECRET-KEY", result.Data.Properties["sharedKey"]);
        Assert.Equal(1, h.Authenticator.BeginCalls);
        Assert.False(h.Enabled);
        h.TwoFactor.Verify(t => t.SetTwoFactorEnabledAsync(It.IsAny<IdentityUser<int>>(), It.IsAny<bool>()), Times.Never);
        h.Reauthenticator.Verify(r => r.IsReauthenticatedAsync(h.User, Proof, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Setup_MethodNameIsCaseInsensitive() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();

        Assert.True((await h.Service.BeginSetupAsync(h.User, "Authenticator", Proof, h.Token)).Succeeded);
    }

    [Fact]
    public async Task Setup_WithoutFreshProof_IsForbidden_AndNothingIsStarted() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        h.Reauthenticated = false;

        var result = await h.Service.BeginSetupAsync(h.User, "authenticator", Proof, h.Token);

        Assert.False(result.Succeeded);
        Assert.Equal(ResultCode.Forbidden, result.Code);
        Assert.Equal("ReauthenticationRequired", result.Errors.Single().Code);
        Assert.Equal(0, h.Authenticator.BeginCalls);
        Assert.Null(result.Data);
        Assert.DoesNotContain("SECRET-KEY", System.Text.Json.JsonSerializer.Serialize(result));
    }

    [Fact]
    public async Task Setup_WithoutAnyRequestBody_IsForbidden() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        h.Reauthenticated = false;

        var result = await h.Service.BeginSetupAsync(h.User, "authenticator", null, h.Token);

        Assert.Equal(ResultCode.Forbidden, result.Code);
        Assert.Equal(0, h.Authenticator.BeginCalls);
    }

    [Fact]
    public async Task Setup_WhileTwoFactorIsEnabled_IsConflict_EvenWithFreshProof() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        h.Enabled = true;

        var result = await h.Service.BeginSetupAsync(h.User, "authenticator", Proof, h.Token);

        Assert.Equal(ResultCode.Conflict, result.Code);
        Assert.Equal("TwoFactorAlreadyEnabled", result.Errors.Single().Code);
        Assert.Equal(0, h.Authenticator.BeginCalls);
    }

    [Fact]
    public async Task Setup_WhileEnabled_WithoutProof_RevealsNothingAboutTheState() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        h.Enabled = true;
        h.Reauthenticated = false;

        var result = await h.Service.BeginSetupAsync(h.User, "authenticator", Proof, h.Token);

        Assert.Equal(ResultCode.Forbidden, result.Code);
    }

    [Theory]
    [InlineData("sms-typo")]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public async Task Setup_UnknownOrBlankMethod_IsBadRequest_BeforeAnyPasswordIsChecked(string method) {
        await using var h = await TwoFactorManagementHarness.CreateAsync();

        var result = await h.Service.BeginSetupAsync(h.User, method, Proof, h.Token);

        Assert.Equal(ResultCode.BadRequest, result.Code);
        Assert.Equal("InvalidTwoFactorMethod", result.Errors.Single().Code);
        h.Reauthenticator.Verify(r => r.IsReauthenticatedAsync(It.IsAny<IdentityUser<int>>(), It.IsAny<TwoFactorReauthenticationModel>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Setup_DeliveryMethod_StartsThatMethodOnly() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();

        Assert.True((await h.Service.BeginSetupAsync(h.User, "sms", Proof, h.Token)).Succeeded);

        Assert.Equal(1, h.Other.BeginCalls);
        Assert.Equal(0, h.Authenticator.BeginCalls);
    }

    [Fact]
    public async Task Setup_MethodFailure_IsNotHiddenAsAClientError() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        h.Authenticator.BeginException = new InvalidOperationException("key store down");

        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.BeginSetupAsync(h.User, "authenticator", Proof, h.Token));
    }

    [Fact]
    public async Task Setup_CancelledToken_ThrowsAndStartsNothing() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Service.BeginSetupAsync(h.User, "authenticator", Proof, cts.Token));

        Assert.Equal(0, h.Authenticator.BeginCalls);
    }
}
