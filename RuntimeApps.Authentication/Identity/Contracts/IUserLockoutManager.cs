using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Identity.Contracts {
    public interface IUserLockoutManager<TUser> where TUser : class {
        Task<bool> IsLockedOutAsync(TUser user); 
        Task<IdentityResult> SetLockoutEnabledAsync(TUser user, bool enabled); 
        Task<IdentityResult> SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd); 
        Task<IdentityResult> AccessFailedAsync(TUser user); 
        Task<IdentityResult> ResetAccessFailedCountAsync(TUser user);
    }
}
