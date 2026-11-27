using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

public class TwoFactorLoginStartTest {
    private static readonly DateTimeOffset Expires = new(2026, 1, 1, 0, 5, 0, TimeSpan.Zero);

    [Fact]
    public void SignIn_HasNoChallenge() {
        var start = TwoFactorLoginStart.SignIn();

        Assert.True(start.SignInAllowed);
        Assert.Null(start.Challenge);
        Assert.Null(start.ExpiresAt);
        Assert.Empty(start.Methods);
    }

    [Fact]
    public void Required_CarriesChallengeExpiryAndMethods() {
        var start = TwoFactorLoginStart.Required("handle", Expires, [new TwoFactorMethodInfo("authenticator", false)]);

        Assert.False(start.SignInAllowed);
        Assert.Equal("handle", start.Challenge);
        Assert.Equal(Expires, start.ExpiresAt);
        Assert.Equal("authenticator", Assert.Single(start.Methods).Name);
    }

    [Fact]
    public void Required_AllowsEmptyMethodListButNotMissingChallenge() {
        Assert.Empty(TwoFactorLoginStart.Required("handle", Expires, []).Methods);

        Assert.Throws<ArgumentException>(() => TwoFactorLoginStart.Required(" ", Expires, []));
        Assert.Throws<ArgumentNullException>(() => TwoFactorLoginStart.Required("handle", Expires, null));
    }
}
