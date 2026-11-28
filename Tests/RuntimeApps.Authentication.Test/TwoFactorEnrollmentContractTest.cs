using System.ComponentModel.DataAnnotations;
using System.Reflection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.TwoFactor.Services;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.Test;

public class TwoFactorEnrollmentContractTest {
    private static AuthenticatorTwoFactorMethod<IdentityUser> CreateMethod(Mock<IUserTwoFactorManager<IdentityUser>> manager) =>
        new(manager.Object, new Mock<UserManager<IdentityUser>>(Mock.Of<IUserStore<IdentityUser>>(), null, null, null, null, null, null, null, null).Object,
            Options.Create(new TwoFactorOptions { Issuer = "Acme" }));

    [Fact]
    public async Task Authenticator_ClearEnrollment_RotatesTheKey() {
        var manager = new Mock<IUserTwoFactorManager<IdentityUser>>();
        var user = new IdentityUser();
        manager.Setup(m => m.ResetAuthenticatorKeyAsync(user)).ReturnsAsync(IdentityResult.Success);

        await ((ITwoFactorMethod<IdentityUser>)CreateMethod(manager)).ClearEnrollmentAsync(user, TestContext.Current.CancellationToken);

        manager.Verify(m => m.ResetAuthenticatorKeyAsync(user), Times.Once);
    }

    [Fact]
    public async Task Authenticator_ClearEnrollment_FailsLoudlyWhenTheKeyCannotBeReset() {
        var manager = new Mock<IUserTwoFactorManager<IdentityUser>>();
        manager.Setup(m => m.ResetAuthenticatorKeyAsync(It.IsAny<IdentityUser>())).ReturnsAsync(IdentityResult.Failed());

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            CreateMethod(manager).ClearEnrollmentAsync(new IdentityUser(), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Authenticator_ClearEnrollment_HonorsCancellationBeforeStarting() {
        var manager = new Mock<IUserTwoFactorManager<IdentityUser>>();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CreateMethod(manager).ClearEnrollmentAsync(new IdentityUser(), cts.Token));

        manager.Verify(m => m.ResetAuthenticatorKeyAsync(It.IsAny<IdentityUser>()), Times.Never);
    }

    [Fact]
    public async Task CustomMethodWithoutOverride_ClearEnrollmentIsANoOp() {
        ITwoFactorMethod<IdentityUser> method = new TwoFactorFoundationsTest.FakeSmsMethod();

        await method.ClearEnrollmentAsync(new IdentityUser(), TestContext.Current.CancellationToken);
    }

    [Fact]
    public void ConfirmAndDisableModels_RequireTheirCodes() {
        Assert.NotNull(typeof(TwoFactorConfirmModel).GetProperty(nameof(TwoFactorConfirmModel.Code))!.GetCustomAttribute<RequiredAttribute>());
        Assert.NotNull(typeof(TwoFactorDisableModel).GetProperty(nameof(TwoFactorDisableModel.Code))!.GetCustomAttribute<RequiredAttribute>());
        Assert.NotNull(typeof(TwoFactorDisableModel).GetProperty(nameof(TwoFactorDisableModel.Method))!.GetCustomAttribute<RequiredAttribute>());
    }

    [Fact]
    public void ReauthenticationFields_AreOptionalOnTheBaseModel_AndInheritedByDisable() {
        foreach(var name in new[] { nameof(TwoFactorReauthenticationModel.CurrentPassword), nameof(TwoFactorReauthenticationModel.ReauthenticationProvider), nameof(TwoFactorReauthenticationModel.ReauthenticationToken) })
            Assert.Null(typeof(TwoFactorReauthenticationModel).GetProperty(name)!.GetCustomAttribute<RequiredAttribute>());
        Assert.True(typeof(TwoFactorReauthenticationModel).IsAssignableFrom(typeof(TwoFactorDisableModel)));
    }

    [Fact]
    public void StatusRecords_CarryOnlyNamesAndFlags() {
        var status = new TwoFactorStatus(true, [new TwoFactorMethodStatus("authenticator", false, true)]);

        Assert.True(status.Enabled);
        Assert.Equal(new TwoFactorMethodStatus("authenticator", false, true), Assert.Single(status.Methods));
        Assert.All(typeof(TwoFactorMethodStatus).GetProperties(), p => Assert.True(p.PropertyType == typeof(string) || p.PropertyType == typeof(bool)));
    }
}
