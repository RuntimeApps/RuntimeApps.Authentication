using System.Text.Json;
using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

public class TwoFactorLoginModelsTest {
    private static readonly DateTimeOffset Expires = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ContinuationResponse_Default_KeepsExistingShape() {
        var json = JsonSerializer.Serialize(new AuthenticationContinuationResponse());

        Assert.Equal("{\"RequiresTwoFactor\":true}", json);
    }

    [Fact]
    public void ContinuationResponse_WithChallenge_IncludesChallengeExpiryAndMethods() {
        var response = new AuthenticationContinuationResponse {
            TwoFactorChallenge = "handle", ExpiresAt = Expires,
            Methods = [new TwoFactorMethodInfo("authenticator", false), new TwoFactorMethodInfo("sms", true)]
        };

        using var document = JsonDocument.Parse(JsonSerializer.Serialize(response));
        var root = document.RootElement;

        Assert.True(root.GetProperty("RequiresTwoFactor").GetBoolean());
        Assert.Equal("handle", root.GetProperty("TwoFactorChallenge").GetString());
        Assert.Equal(Expires, root.GetProperty("ExpiresAt").GetDateTimeOffset());
        var methods = root.GetProperty("Methods").EnumerateArray().ToArray();
        Assert.Equal(2, methods.Length);
        Assert.Equal("sms", methods[1].GetProperty("Name").GetString());
        Assert.True(methods[1].GetProperty("RequiresSend").GetBoolean());
    }

    [Fact]
    public void ContinuationResponse_EmptyMethodList_IsKeptAsEmptyArray() {
        var json = JsonSerializer.Serialize(new AuthenticationContinuationResponse { TwoFactorChallenge = "h", Methods = [] });

        using var document = JsonDocument.Parse(json);
        Assert.Equal(JsonValueKind.Array, document.RootElement.GetProperty("Methods").ValueKind);
        Assert.Equal(0, document.RootElement.GetProperty("Methods").GetArrayLength());
    }

    [Fact]
    public void ContinuationResponse_NeverExposesTokenMembers() {
        var names = typeof(AuthenticationContinuationResponse).GetProperties().Select(p => p.Name).ToArray();

        Assert.DoesNotContain(names, name => name.Contains("Token", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(names, name => name.Contains("Refresh", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Token_WithoutTwoFactorFields_DoesNotSerializeThem() {
        var json = JsonSerializer.Serialize(new Token { AuthenticationToken = "jwt" });

        Assert.DoesNotContain("TwoFactor", json);
    }

    [Fact]
    public void Token_CarriesChallengeFieldsWhenSet() {
        var token = new Token { TwoFactorChallenge = "handle", TwoFactorExpiresAt = Expires, TwoFactorMethods = [new TwoFactorMethodInfo("authenticator", false)] };

        using var document = JsonDocument.Parse(JsonSerializer.Serialize(token));

        Assert.Equal("handle", document.RootElement.GetProperty("TwoFactorChallenge").GetString());
        Assert.Equal(1, document.RootElement.GetProperty("TwoFactorMethods").GetArrayLength());
    }
}
