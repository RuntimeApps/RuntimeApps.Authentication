using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Identity.Contracts {
    public interface IUserTokenManager<TUser> where TUser : class {
        Task<string> GetAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName); 
        Task<IdentityResult> SetAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName, string tokenValue); 
        Task<IdentityResult> RemoveAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName);
    }
}
