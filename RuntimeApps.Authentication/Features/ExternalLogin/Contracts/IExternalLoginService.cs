using RuntimeApps.Authentication.Features.ExternalLogin.Models;
using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Features.ExternalLogin.Contracts {
    /// <summary>
    /// Resolves local accounts for validated external identities and manages the external logins of an
    /// authenticated account. Login, link and unlink are separate operations. Provider token validation
    /// stays in <see cref="IExternalLoginProvider{TUser}"/>.
    /// </summary>
    /// <remarks>
    /// ASP.NET Core Identity manager calls used here do not accept cancellation tokens. Cancellation is
    /// checked before writes begin and is not observed between dependent writes.
    /// </remarks>
    public interface IExternalLoginService<TUser> where TUser : class {
        /// <summary>
        /// Validates the provider token and returns the local account for it: an account already linked to
        /// the identity, an existing account matched by a trusted email, or a newly created account.
        /// Failures are deliberately generic.
        /// </summary>
        Task<Result<TUser>> ResolveLoginAsync(string provider, string token, CancellationToken cancellationToken = default);

        /// <summary>Links an external identity to <paramref name="user"/> after re-authentication.</summary>
        Task<Result> LinkAsync(TUser user, LinkExternalLoginModel request, CancellationToken cancellationToken = default);

        /// <summary>Unlinks the provider's identity unless it is the account's last usable authentication method.</summary>
        Task<Result> UnlinkAsync(TUser user, string provider, CancellationToken cancellationToken = default);

        Task<IReadOnlyList<ExternalLoginSummary>> ListLoginsAsync(TUser user, CancellationToken cancellationToken = default);
    }
}
