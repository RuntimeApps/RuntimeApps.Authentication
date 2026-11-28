using Microsoft.Extensions.Configuration;
using RuntimeApps.Authentication.Features.TwoFactor.Models;

namespace RuntimeApps.Authentication.Test;

public class TwoFactorLoginOptionsTest {
    [Fact]
    public void Defaults_AreFailClosedWithModerateRequestLimit() {
        var options = new TwoFactorOptions { Issuer = "Acme" };

        options.Validate();

        Assert.Equal(TwoFactorNoMethodBehavior.RequireTwoFactor, options.NoEnrolledMethodBehavior);
        Assert.Equal(10, options.CompleteRequestsPerMinute);
        Assert.Equal(5, options.MaxAttemptsPerChallenge);
    }

    [Theory]
    [InlineData(TwoFactorNoMethodBehavior.RequireTwoFactor)]
    [InlineData(TwoFactorNoMethodBehavior.AllowSignIn)]
    public void NoEnrolledMethodBehavior_AcceptsDefinedValues(TwoFactorNoMethodBehavior behavior) =>
        new TwoFactorOptions { Issuer = "Acme", NoEnrolledMethodBehavior = behavior }.Validate();

    [Fact]
    public void NoEnrolledMethodBehavior_RejectsUndefinedValue() =>
        Assert.Throws<InvalidOperationException>(() =>
            new TwoFactorOptions { Issuer = "Acme", NoEnrolledMethodBehavior = (TwoFactorNoMethodBehavior)42 }.Validate());

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(1001)]
    public void CompleteRequestsPerMinute_RejectsOutOfRange(int value) =>
        Assert.Throws<InvalidOperationException>(() =>
            new TwoFactorOptions { Issuer = "Acme", CompleteRequestsPerMinute = value }.Validate());

    [Theory]
    [InlineData(1)]
    [InlineData(1000)]
    public void CompleteRequestsPerMinute_AcceptsBounds(int value) =>
        new TwoFactorOptions { Issuer = "Acme", CompleteRequestsPerMinute = value }.Validate();

    [Fact]
    public void NewOptions_BindFromConfiguration() {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["NoEnrolledMethodBehavior"] = "AllowSignIn",
            ["CompleteRequestsPerMinute"] = "25"
        }).Build();
        var options = new TwoFactorOptions { Issuer = "Acme" };

        configuration.Bind(options);

        Assert.Equal(TwoFactorNoMethodBehavior.AllowSignIn, options.NoEnrolledMethodBehavior);
        Assert.Equal(25, options.CompleteRequestsPerMinute);
    }

    [Fact]
    public void ExternalLoginPolicy_DefaultsToRequireWhenEnabled() {
        var options = new TwoFactorOptions { Issuer = "Acme" };

        options.Validate();

        Assert.Equal(TwoFactorExternalLoginPolicy.RequireWhenEnabled, options.ExternalLoginPolicy);
    }

    [Theory]
    [InlineData(TwoFactorExternalLoginPolicy.RequireWhenEnabled)]
    [InlineData(TwoFactorExternalLoginPolicy.TrustProvider)]
    public void ExternalLoginPolicy_AcceptsDefinedValues(TwoFactorExternalLoginPolicy policy) =>
        new TwoFactorOptions { Issuer = "Acme", ExternalLoginPolicy = policy }.Validate();

    [Fact]
    public void ExternalLoginPolicy_RejectsUndefinedValue() =>
        Assert.Throws<InvalidOperationException>(() =>
            new TwoFactorOptions { Issuer = "Acme", ExternalLoginPolicy = (TwoFactorExternalLoginPolicy)42 }.Validate());

    [Fact]
    public void ExternalLoginPolicy_BindsFromConfiguration() {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["ExternalLoginPolicy"] = "TrustProvider"
        }).Build();
        var options = new TwoFactorOptions { Issuer = "Acme" };

        configuration.Bind(options);

        Assert.Equal(TwoFactorExternalLoginPolicy.TrustProvider, options.ExternalLoginPolicy);
    }
}
