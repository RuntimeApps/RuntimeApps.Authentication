using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Identity.Contracts {
    /// <remarks>Identity claim operations do not accept cancellation tokens; handlers check cancellation before starting writes.</remarks>
    public interface IUserClaimManager<TUser> where TUser : class {
        Task<IdentityResult> AddClaimAsync(TUser user, Claim claim);
        Task<IdentityResult> AddClaimsAsync(TUser user, IEnumerable<Claim> claims);
        Task<IdentityResult> ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim);
        Task<IdentityResult> RemoveClaimAsync(TUser user, Claim claim);
        Task<IdentityResult> RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims);
        Task<IList<Claim>> GetClaimsAsync(TUser user);
        Task<IList<TUser>> GetUsersForClaimAsync(Claim claim);
    }
}
