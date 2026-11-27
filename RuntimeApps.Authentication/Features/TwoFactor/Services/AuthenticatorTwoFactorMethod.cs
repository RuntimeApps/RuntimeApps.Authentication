using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.Features.TwoFactor.Services;

/// <summary>
/// Time-based one-time passwords (RFC 6238) using Identity's authenticator key and token provider.
/// Replay of a code inside its validity window is prevented by the framework, not by this class.
/// </summary>
public sealed class AuthenticatorTwoFactorMethod<TUser>(
    IUserTwoFactorManager<TUser> twoFactorManager,
    UserManager<TUser> userManager,
    IOptions<TwoFactorOptions> options) : ITwoFactorMethod<TUser> where TUser : class {
    public const string MethodName = "authenticator";
    public const string SharedKeyProperty = "sharedKey";
    public const string AuthenticatorUriProperty = "authenticatorUri";
    private const int CodeLength = 6;

    public string Name => MethodName;
    public bool IsDeliveryBased => false;

    public async Task<bool> IsEnrolledAsync(TUser user, CancellationToken cancellationToken) {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();
        return await twoFactorManager.GetTwoFactorEnabledAsync(user)
            && !string.IsNullOrEmpty(await twoFactorManager.GetAuthenticatorKeyAsync(user));
    }

    public async Task<TwoFactorEnrollmentInfo> BeginEnrollmentAsync(TUser user, CancellationToken cancellationToken) {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();
        // Rotating the key of an enrolled user would lock them out of their current authenticator.
        if(await IsEnrolledAsync(user, cancellationToken))
            throw new InvalidOperationException("The authenticator method is already enrolled for this user.");

        var reset = await twoFactorManager.ResetAuthenticatorKeyAsync(user);
        if(!reset.Succeeded)
            throw new InvalidOperationException("The authenticator key could not be created.");
        var key = await twoFactorManager.GetAuthenticatorKeyAsync(user);
        if(string.IsNullOrEmpty(key))
            throw new InvalidOperationException("The authenticator key could not be created.");

        var issuer = Uri.EscapeDataString(options.Value.Issuer);
        var account = Uri.EscapeDataString(await GetAccountNameAsync(user));
        var uri = $"otpauth://totp/{issuer}:{account}?secret={key}&issuer={issuer}&digits={CodeLength}";
        return new TwoFactorEnrollmentInfo(Name, new Dictionary<string, string> {
            [SharedKeyProperty] = FormatKey(key),
            [AuthenticatorUriProperty] = uri
        });
    }

    public Task<bool> ConfirmEnrollmentAsync(TUser user, string code, CancellationToken cancellationToken) =>
        VerifyAsync(user, code, cancellationToken);

    public async Task<bool> VerifyAsync(TUser user, string code, CancellationToken cancellationToken) {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();
        if(!TryNormalizeCode(code, out var normalized)) return false;
        return await twoFactorManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, normalized);
    }

    /// <summary>Removes spaces and hyphens and accepts exactly six ASCII digits.</summary>
    internal static bool TryNormalizeCode(string code, out string normalized) {
        normalized = null;
        if(string.IsNullOrWhiteSpace(code) || code.Length > 32) return false;
        var builder = new StringBuilder(CodeLength);
        foreach(var c in code) {
            if(c is ' ' or '-') continue;
            if(c is < '0' or > '9') return false;
            builder.Append(c);
        }
        if(builder.Length != CodeLength) return false;
        normalized = builder.ToString();
        return true;
    }

    private async Task<string> GetAccountNameAsync(TUser user) {
        var name = await userManager.GetEmailAsync(user);
        if(string.IsNullOrWhiteSpace(name)) name = await userManager.GetUserNameAsync(user);
        if(string.IsNullOrWhiteSpace(name)) name = await userManager.GetUserIdAsync(user);
        return name;
    }

    /// <summary>Groups the key in blocks of four for manual entry.</summary>
    private static string FormatKey(string key) {
        var builder = new StringBuilder(key.Length + key.Length / 4);
        for(var i = 0; i < key.Length; i += 4) {
            if(i > 0) builder.Append(' ');
            builder.Append(key, i, Math.Min(4, key.Length - i));
        }
        return builder.ToString();
    }
}
