using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Identity.Contracts {
    /// <remarks>
    /// These methods wrap ASP.NET Core Identity APIs that do not accept cancellation tokens.
    /// HTTP callers should check cancellation before starting an operation; an operation already
    /// started must be allowed to finish so its persisted state is not reported as cancelled.
    /// </remarks>
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
