using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.TwoFactor.Services;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.Test;

public class TwoFactorCodeNormalizationTest {
    private static ITwoFactorMethod<IdentityUser> CustomMethod() => new TwoFactorFoundationsTest.FakeSmsMethod();

    private static ITwoFactorMethod<IdentityUser> Authenticator() => new AuthenticatorTwoFactorMethod<IdentityUser>(
        Mock.Of<IUserTwoFactorManager<IdentityUser>>(),
        new Mock<UserManager<IdentityUser>>(Mock.Of<IUserStore<IdentityUser>>(), null, null, null, null, null, null, null, null).Object,
        Options.Create(new TwoFactorOptions { Issuer = "Acme" }));

    [Theory]
    [InlineData("123456", "123456")]
    [InlineData(" 12 34 56 ", "123456")]
    [InlineData("AB\tCD", "ABCD")]
    [InlineData("12-34", "12-34")] // the default keeps hyphens; only whitespace is removed
    public void Default_RemovesWhitespaceOnly(string input, string expected) =>
        Assert.Equal(expected, CustomMethod().NormalizeCode(input));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Default_RejectsEmptyInput(string input) => Assert.Null(CustomMethod().NormalizeCode(input));

    [Fact]
    public void Default_RejectsOverlongInput() {
        Assert.Null(CustomMethod().NormalizeCode(new string('1', 33)));
        Assert.Null(CustomMethod().NormalizeCode(new string('1', 65)));
        Assert.NotNull(CustomMethod().NormalizeCode(new string('1', 32)));
    }

    [Theory]
    [InlineData("123456", "123456")]
    [InlineData(" 123 456 ", "123456")]
    [InlineData("123-456", "123456")]
    public void Authenticator_ReturnsCanonicalDigits(string input, string expected) =>
        Assert.Equal(expected, Authenticator().NormalizeCode(input));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12345a")]
    [InlineData("+12345")]
    public void Authenticator_RejectsMalformedCodes(string input) => Assert.Null(Authenticator().NormalizeCode(input));

    [Fact]
    public void Authenticator_EquivalentSubmissionsShareOneCanonicalForm() {
        var method = Authenticator();

        Assert.Equal(method.NormalizeCode("123456"), method.NormalizeCode("123 456"));
        Assert.Equal(method.NormalizeCode("123456"), method.NormalizeCode("123-456"));
    }
}
