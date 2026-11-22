using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Identity.Contracts {
    /// <remarks>Identity role assignment calls do not accept cancellation tokens; handlers check cancellation before starting writes.</remarks>
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
