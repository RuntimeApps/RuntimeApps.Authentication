using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Identity.Contracts {
    /// <remarks>
    /// Identity role manager operations do not expose cancellation overloads. Endpoint handlers
    /// check cancellation before starting these calls and allow an in-flight write to complete.
    /// </remarks>
    public interface IRoleManager<TRole>: IDisposable where TRole : class {
        IQueryable<TRole> Roles { get; }
        Task<IdentityResult> CreateAsync(TRole role);
        Task<IdentityResult> UpdateAsync(TRole role);
        Task<IdentityResult> DeleteAsync(TRole role);
        Task<bool> RoleExistsAsync(string roleName);
        Task<TRole> FindByIdAsync(string roleId);
        Task<TRole> FindByNameAsync(string roleName);
        Task<IdentityResult> AddClaimAsync(TRole role, Claim claim);
        Task<IdentityResult> RemoveClaimAsync(TRole role, Claim claim);
        Task<IList<Claim>> GetClaimsAsync(TRole role);
    }
}
