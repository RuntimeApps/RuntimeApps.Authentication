using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Features.ExternalLogin.Contracts {
    /// <summary>
    /// Resolves local accounts for validated external identities. Provider token validation stays in
    /// <see cref="IExternalLoginProvider{TUser}"/>.
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
    }
}
