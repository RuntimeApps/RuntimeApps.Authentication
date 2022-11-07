using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Interface {
    public interface IUserManager<TUser>
        where TUser : class {
        string GetUserName(ClaimsPrincipal principal);
        string GetUserId(ClaimsPrincipal principal);
        Task<TUser> GetUserAsync(ClaimsPrincipal principal);


        Task<IdentityResult> CreateAsync(TUser user);
        Task<IdentityResult> CreateAsync(TUser user, string password);
        Task<IdentityResult> UpdateAsync(TUser user);
        Task<IdentityResult> DeleteAsync(TUser user);
        Task<TUser> FindByIdAsync(string userId);
        Task<TUser> FindByNameAsync(string userName);
        
        Task<bool> CheckPasswordAsync(TUser user, string password);
        Task<IdentityResult> AddPasswordAsync(TUser user, string password);
        Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword);
        Task<IdentityResult> RemovePasswordAsync(TUser user);
        Task<string> GeneratePasswordResetTokenAsync(TUser user);
        Task<IdentityResult> ResetPasswordAsync(TUser user, string token, string newPassword);
        
        Task<TUser> FindByLoginAsync(string loginProvider, string providerKey);
        Task<IdentityResult> RemoveLoginAsync(TUser user, string loginProvider, string providerKey);
        Task<IdentityResult> AddLoginAsync(TUser user, UserLoginInfo login);
        Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user);
        
        Task<IdentityResult> AddClaimAsync(TUser user, Claim claim);
        Task<IdentityResult> AddClaimsAsync(TUser user, IEnumerable<Claim> claims);
        Task<IdentityResult> ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim);
        Task<IdentityResult> RemoveClaimAsync(TUser user, Claim claim);
        Task<IdentityResult> RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims);
        Task<IList<Claim>> GetClaimsAsync(TUser user);
        
        Task<IdentityResult> AddToRoleAsync(TUser user, string role);
        Task<IdentityResult> AddToRolesAsync(TUser user, IEnumerable<string> roles);
        Task<IdentityResult> RemoveFromRoleAsync(TUser user, string role);
        Task<IdentityResult> RemoveFromRolesAsync(TUser user, IEnumerable<string> roles);
        Task<IList<string>> GetRolesAsync(TUser user);
        Task<bool> IsInRoleAsync(TUser user, string role);
        
        Task<IdentityResult> SetEmailAsync(TUser user, string email);
        Task<TUser> FindByEmailAsync(string email);
        Task<string> GenerateEmailConfirmationTokenAsync(TUser user);
        Task<IdentityResult> ConfirmEmailAsync(TUser user, string token);
        Task<string> GenerateChangeEmailTokenAsync(TUser user, string newEmail);
        Task<IdentityResult> ChangeEmailAsync(TUser user, string newEmail, string token);
        
        Task<IdentityResult> SetPhoneNumberAsync(TUser user, string phoneNumber);
        Task<IdentityResult> ChangePhoneNumberAsync(TUser user, string phoneNumber, string token);
        Task<string> GenerateChangePhoneNumberTokenAsync(TUser user, string phoneNumber);
        
        void RegisterTokenProvider(string providerName, IUserTwoFactorTokenProvider<TUser> provider);
        Task<IList<string>> GetValidTwoFactorProvidersAsync(TUser user);
        Task<bool> VerifyTwoFactorTokenAsync(TUser user, string tokenProvider, string token);
        Task<string> GenerateTwoFactorTokenAsync(TUser user, string tokenProvider);
        Task<IdentityResult> SetTwoFactorEnabledAsync(TUser user, bool enabled);
        Task<bool> IsLockedOutAsync(TUser user);
        Task<IdentityResult> SetLockoutEnabledAsync(TUser user, bool enabled);
        Task<IdentityResult> SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd);
        Task<IdentityResult> AccessFailedAsync(TUser user);
        Task<IdentityResult> ResetAccessFailedCountAsync(TUser user);
        Task<IList<TUser>> GetUsersForClaimAsync(Claim claim);
        Task<IList<TUser>> GetUsersInRoleAsync(string roleName);
        Task<string> GetAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName);
        Task<IdentityResult> SetAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName, string tokenValue);
        Task<IdentityResult> RemoveAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName);
        Task<string> GetAuthenticatorKeyAsync(TUser user);
        Task<IdentityResult> ResetAuthenticatorKeyAsync(TUser user);
    }
}
