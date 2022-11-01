using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Interface {
    public interface ISignInManager<TUser> where TUser : class {
        Task<ClaimsPrincipal> CreateUserPrincipalAsync(TUser user);

        bool IsSignedIn(ClaimsPrincipal principal);
        Task<bool> CanSignInAsync(TUser user);
        Task RefreshSignInAsync(TUser user);
        Task SignInAsync(TUser user, bool isPersistent, string authenticationMethod = null);

        Task SignInAsync(TUser user, AuthenticationProperties authenticationProperties, string authenticationMethod = null);
        Task SignInWithClaimsAsync(TUser user, bool isPersistent, IEnumerable<Claim> additionalClaims);

        Task<SignInResult> PasswordSignInAsync(TUser user, string password, bool isPersistent, bool lockoutOnFailure);
        Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure);
        Task<SignInResult> CheckPasswordSignInAsync(TUser user, string password, bool lockoutOnFailure);
        
        Task<bool> IsTwoFactorClientRememberedAsync(TUser user);
        Task RememberTwoFactorClientAsync(TUser user);
        Task ForgetTwoFactorClientAsync();
        Task<SignInResult> TwoFactorRecoveryCodeSignInAsync(string recoveryCode);
        Task<SignInResult> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient);
        Task<SignInResult> TwoFactorSignInAsync(string provider, string code, bool isPersistent, bool rememberClient);
        Task<TUser> GetTwoFactorAuthenticationUserAsync();

        Task<SignInResult> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent);
        Task<SignInResult> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent, bool bypassTwoFactor);
        Task<IEnumerable<AuthenticationScheme>> GetExternalAuthenticationSchemesAsync();
        Task<ExternalLoginInfo> GetExternalLoginInfoAsync(string expectedXsrf = null);
        Task<IdentityResult> UpdateExternalAuthenticationTokensAsync(ExternalLoginInfo externalLogin);

        AuthenticationProperties ConfigureExternalAuthenticationProperties(string provider, string redirectUrl, string userId = null);
    }
}
