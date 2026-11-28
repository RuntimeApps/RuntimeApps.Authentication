using Microsoft.AspNetCore.Identity;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.Features.TwoFactor.Services;

/// <summary>
/// Checks fresh proof of control of an account before two-factor setup changes: the current password, or a fresh
/// token from a provider already linked to the account. Mirrors the re-authentication of external-login linking.
/// </summary>
public class TwoFactorReauthenticator<TUser>(
    IUserLockoutManager<TUser> lockoutManager,
    IUserPasswordManager<TUser> passwordManager,
    ISignInManager<TUser> signInManager,
    IUserLoginManager<TUser> loginManager,
    IEnumerable<IExternalLoginProvider<TUser>> providers) where TUser : class {
    /// <summary>
    /// True only when the proof is valid. A locked-out account never passes. When a password is supplied it alone
    /// decides: a wrong password does not fall back to the provider token. A wrong password counts toward lockout.
    /// </summary>
    public virtual async Task<bool> IsReauthenticatedAsync(TUser user, TwoFactorReauthenticationModel request, CancellationToken cancellationToken = default) {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();
        if(request == null)
            return false;
        if(await lockoutManager.IsLockedOutAsync(user))
            return false;

        if(!string.IsNullOrEmpty(request.CurrentPassword)) {
            if(!await passwordManager.HasPasswordAsync(user))
                return false;
            // Counts failures toward lockout, like a password sign-in.
            var check = await signInManager.CheckPasswordSignInAsync(user, request.CurrentPassword, true);
            return check?.Succeeded == true;
        }

        if(string.IsNullOrWhiteSpace(request.ReauthenticationProvider) || string.IsNullOrWhiteSpace(request.ReauthenticationToken))
            return false;
        var provider = providers.FirstOrDefault(item => string.Equals(item.Provider, request.ReauthenticationProvider, StringComparison.OrdinalIgnoreCase));
        if(provider == null)
            return false;
        var identity = await provider.ValidateAsync(request.ReauthenticationToken, cancellationToken);
        if(identity?.LoginInfo == null)
            return false;
        // The fresh identity must be one that is already linked to this very account.
        var logins = await loginManager.GetLoginsAsync(user);
        return logins.Any(login =>
            string.Equals(login.LoginProvider, identity.LoginInfo.LoginProvider, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(login.ProviderKey, identity.LoginInfo.ProviderKey, StringComparison.Ordinal));
    }
}
