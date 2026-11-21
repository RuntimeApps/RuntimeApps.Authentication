using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Identity.Contracts {
    public interface IUserRoleManager<TUser> where TUser : class {
        Task<IdentityResult> AddToRoleAsync(TUser user, string role); 
        Task<IdentityResult> AddToRolesAsync(TUser user, IEnumerable<string> roles); 
        Task<IdentityResult> RemoveFromRoleAsync(TUser user, string role); 
        Task<IdentityResult> RemoveFromRolesAsync(TUser user, IEnumerable<string> roles); 
        Task<IList<string>> GetRolesAsync(TUser user); 
        Task<bool> IsInRoleAsync(TUser user, string role); 
        Task<IList<TUser>> GetUsersInRoleAsync(string roleName);
    }
}
