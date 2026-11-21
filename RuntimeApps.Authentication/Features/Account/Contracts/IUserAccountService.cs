using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Features.Account.Contracts {
    public interface IUserAccountService<TUser> {
        Task<Result<TUser, Token>> CompleteRegistrationAsync(TUser user);
        Task<Result<TUser, Token>> LoginAsync(string userName, string password);
        Task<Result<TUser, Token>> ExternalLoginAsync(string provider, string token);
    }
}
