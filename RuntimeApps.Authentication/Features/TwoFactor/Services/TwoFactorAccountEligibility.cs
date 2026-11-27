using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.Features.TwoFactor.Services;

/// <summary>
/// Decides whether an account may still sign in when a second factor is completed. The password or external
/// step happened earlier, so the account is checked again with the same rules the refresh endpoint applies:
/// not locked out, email policy satisfied and, for confirmed accounts, allowed by the sign-in manager.
/// </summary>
public class TwoFactorAccountEligibility<TUser, TKey>(
    IUserLockoutManager<TUser> lockoutManager,
    IUserLoginManager<TUser> loginManager,
    ISignInManager<TUser> signInManager,
    IOptions<VerificationOptions> verificationOptions)
    where TUser : IdentityUser<TKey>
    where TKey : IEquatable<TKey> {
    public virtual async Task<bool> IsEligibleAsync(TUser user, CancellationToken cancellationToken = default) {
        if(user == null) return false;
        cancellationToken.ThrowIfCancellationRequested();
        if(await lockoutManager.IsLockedOutAsync(user)) return false;

        var hasExternalLogin = (await loginManager.GetLoginsAsync(user)).Count > 0;
        var emailPolicyAllowsSignIn = user.EmailConfirmed ||
            (hasExternalLogin && !verificationOptions.Value.RequireEmailVerificationForExternalLogins);
        if(!emailPolicyAllowsSignIn) return false;

        return !user.EmailConfirmed || await signInManager.CanSignInAsync(user);
    }
}
