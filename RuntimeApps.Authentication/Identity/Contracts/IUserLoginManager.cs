using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Identity.Contracts {
    public interface IUserLoginManager<TUser> where TUser : class {
        Task<TUser> FindByLoginAsync(string loginProvider, string providerKey); 
        Task<IdentityResult> AddLoginAsync(TUser user, UserLoginInfo login); 
        Task<IdentityResult> RemoveLoginAsync(TUser user, string loginProvider, string providerKey); 
        Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user);
    }
}
