using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Interface {
    public interface IUserAccountService<TUser> {
        Task<Result<TUser, Token>> CompleteRegistrationAsync(TUser user);
        Task<Result<TUser, Token>> LoginAsync(string userName, string password);
        Task<Result<TUser, Token>> ExternalLoginAsync(string provider, string token);
    }
}