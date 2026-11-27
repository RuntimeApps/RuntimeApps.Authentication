using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Identity.Contracts {
    public interface IUserTwoFactorManager<TUser> where TUser : class {
        void RegisterTokenProvider(string providerName, IUserTwoFactorTokenProvider<TUser> provider); 
        Task<IList<string>> GetValidTwoFactorProvidersAsync(TUser user); 
        Task<bool> VerifyTwoFactorTokenAsync(TUser user, string tokenProvider, string token); 
        Task<string> GenerateTwoFactorTokenAsync(TUser user, string tokenProvider); 
        Task<bool> GetTwoFactorEnabledAsync(TUser user); 
        Task<IdentityResult> SetTwoFactorEnabledAsync(TUser user, bool enabled); 
        Task<string> GetAuthenticatorKeyAsync(TUser user); 
        Task<IdentityResult> ResetAuthenticatorKeyAsync(TUser user);
    }
}
