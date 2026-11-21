using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Identity.Contracts {
    public interface IUserEmailManager<TUser> where TUser : class {
        Task<TUser> FindByEmailAsync(string email); 
        Task<IdentityResult> SetEmailAsync(TUser user, string email); 
        Task<string> GenerateEmailConfirmationTokenAsync(TUser user); 
        Task<IdentityResult> ConfirmEmailAsync(TUser user, string token); 
        Task<string> GenerateChangeEmailTokenAsync(TUser user, string newEmail); 
        Task<IdentityResult> ChangeEmailAsync(TUser user, string newEmail, string token);
    }
}
