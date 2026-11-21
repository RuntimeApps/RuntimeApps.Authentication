using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Identity.Contracts {
    public interface IUserManager<TUser> where TUser : class {
        Task<TUser> GetUserAsync(ClaimsPrincipal principal);
        Task<IdentityResult> CreateAsync(TUser user);
        Task<IdentityResult> CreateAsync(TUser user, string password);
        Task<IdentityResult> UpdateAsync(TUser user);
        Task<IdentityResult> DeleteAsync(TUser user);
        Task<TUser> FindByIdAsync(string userId);
        Task<TUser> FindByNameAsync(string userName);
    }
}
