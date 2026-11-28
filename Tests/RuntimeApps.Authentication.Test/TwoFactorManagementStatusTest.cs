using Moq;
using RuntimeApps.Authentication.Features.TwoFactor.Models;

namespace RuntimeApps.Authentication.Test;

public class TwoFactorManagementStatusTest {
    [Fact]
    public async Task Status_ListsEveryRegisteredMethodWithItsEnrollment() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        h.Enabled = true;
        h.Authenticator.Enrolled = true;

        var status = await h.Service.GetStatusAsync(h.User, h.Token);

        Assert.True(status.Enabled);
        Assert.Equal(
            new[] { new TwoFactorMethodStatus("authenticator", false, true), new TwoFactorMethodStatus("sms", true, false) },
            status.Methods);
    }

    [Fact]
    public async Task Status_WhenTwoFactorIsOff_ReportsDisabled() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();

        var status = await h.Service.GetStatusAsync(h.User, h.Token);

        Assert.False(status.Enabled);
        Assert.All(status.Methods, m => Assert.False(m.Enrolled));
    }

    [Fact]
    public async Task Status_NeverStartsEnrollmentOrChangesState() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();

        await h.Service.GetStatusAsync(h.User, h.Token);

        Assert.Equal(0, h.Authenticator.BeginCalls);
        Assert.Equal(0, h.Authenticator.ClearCalls);
        h.TwoFactor.Verify(t => t.SetTwoFactorEnabledAsync(It.IsAny<Microsoft.AspNetCore.Identity.IdentityUser<int>>(), It.IsAny<bool>()), Times.Never);
        Assert.Equal(0, await h.LedgerCountAsync());
    }

    [Fact]
    public async Task Status_DoesNotSwallowMethodFailures() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        h.TwoFactor.Setup(t => t.GetTwoFactorEnabledAsync(It.IsAny<Microsoft.AspNetCore.Identity.IdentityUser<int>>())).ThrowsAsync(new InvalidOperationException("store down"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.GetStatusAsync(h.User, h.Token));
    }

    [Fact]
    public async Task Status_CancelledToken_Throws() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Service.GetStatusAsync(h.User, cts.Token));
    }

    [Fact]
    public async Task Status_NullUser_Throws() {
        await using var h = await TwoFactorManagementHarness.CreateAsync();

        await Assert.ThrowsAsync<ArgumentNullException>(() => h.Service.GetStatusAsync(null, h.Token));
    }
}
