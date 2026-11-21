using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Features.Account.Contracts {
    public enum AuthenticationSessionMode {
        Unspecified = 0,
        Jwt = 1,
        Cookie = 2
    }

    /// <summary>Establishes an authentication session for an account that has already passed eligibility checks.</summary>
    public interface IAuthenticationSessionIssuer<TUser> where TUser : class {
        /// <summary>Identifies the explicitly registered mechanism used by refresh and logout operations.</summary>
        AuthenticationSessionMode Mode => AuthenticationSessionMode.Unspecified;
        Task<Token> IssueAsync(TUser user, CancellationToken cancellationToken = default);
    }
}
