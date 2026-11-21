using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Features.Account.Contracts {
    /// <remarks>ASP.NET Core Identity lookup and sign-in methods currently used by this service do not accept cancellation tokens.</remarks>
    public interface IUserAccountService<TUser> {
        Task<Result<TUser, Token>> CompleteRegistrationAsync(TUser user, CancellationToken cancellationToken = default);
        Task<Result<TUser, Token>> LoginAsync(string userName, string password, CancellationToken cancellationToken = default);
        Task<Result<TUser, Token>> ExternalLoginAsync(string provider, string token, CancellationToken cancellationToken = default);
    }
}
