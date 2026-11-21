using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Features.Account.Contracts {
    /// <summary>Establishes an authentication session for an account that has already passed eligibility checks.</summary>
    public interface IAuthenticationSessionIssuer<TUser> where TUser : class {
        Task<Token> IssueAsync(TUser user, CancellationToken cancellationToken = default);
    }
}
