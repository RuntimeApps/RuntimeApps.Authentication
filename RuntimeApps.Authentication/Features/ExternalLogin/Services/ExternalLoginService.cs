using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Features.ExternalLogin.Services {
    /// <summary>
    /// Default <see cref="IExternalLoginService{TUser}"/>.
    /// <para>
    /// ASP.NET Core Identity saves each manager call separately and this library has no cross-store
    /// transaction, so multi-step operations are ordered so that a failure at any step leaves the account
    /// safe, and operations that can race are re-checked afterwards and undone. A crash between two steps
    /// cannot be repaired by this service.
    /// </para>
    /// </summary>
    public class ExternalLoginService<TUser, TKey>: IExternalLoginService<TUser>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey> {
        private const string GenericFailureCode = "ExternalAuthenticationFailed";
        private const string GenericFailureDescription = "External authentication could not be completed.";

        private readonly IEnumerable<IExternalLoginProvider<TUser>> _providers;
        private readonly IUserManager<TUser> _userManager;
        private readonly IUserLoginManager<TUser> _loginManager;
        private readonly IUserEmailManager<TUser> _emailManager;
        private readonly IUserPasswordManager<TUser> _passwordManager;
        private readonly IExternalLoginEmailTrustPolicy<TUser> _trustPolicy;
        private readonly bool _requireEmailVerification;
        private readonly IRefreshTokenService<TKey> _refreshTokenService;
        private readonly ILogger _logger;

        public ExternalLoginService(IEnumerable<IExternalLoginProvider<TUser>> providers,
                                    IUserManager<TUser> userManager,
                                    IUserLoginManager<TUser> loginManager,
                                    IUserEmailManager<TUser> emailManager,
                                    IUserPasswordManager<TUser> passwordManager,
                                    IExternalLoginEmailTrustPolicy<TUser> trustPolicy = null,
                                    IOptions<VerificationOptions> verificationOptions = null,
                                    IRefreshTokenService<TKey> refreshTokenService = null,
                                    ILogger<ExternalLoginService<TUser, TKey>> logger = null) {
            _providers = providers;
            _userManager = userManager;
            _loginManager = loginManager;
            _emailManager = emailManager;
            _passwordManager = passwordManager;
            _trustPolicy = trustPolicy;
            _requireEmailVerification = verificationOptions?.Value?.RequireEmailVerificationForExternalLogins ?? false;
            _refreshTokenService = refreshTokenService;
            _logger = logger;
        }

        public virtual async Task<Result<TUser>> ResolveLoginAsync(string providerName, string token, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            var provider = FindProvider(providerName);
            if(provider == null)
                return ResolveFailed();

            var providerResult = await provider.ValidateAsync(token, cancellationToken);
            if(providerResult?.LoginInfo == null || providerResult.User == null)
                return ResolveFailed();

            cancellationToken.ThrowIfCancellationRequested();
            var loginInfo = providerResult.LoginInfo;
            // Identity manager/store APIs used below have no CancellationToken overloads.
            var user = await _loginManager.FindByLoginAsync(loginInfo.LoginProvider, loginInfo.ProviderKey);
            cancellationToken.ThrowIfCancellationRequested();
            if(user != null)
                return new Result<TUser>(user);

            var trustedEmail = _trustPolicy?.IsEmailTrusted(provider.Provider, providerResult) == true;
            if(_requireEmailVerification && !trustedEmail)
                return ResolveFailed();

            // An email the policy does not trust is ignored: it is never used to find an account and is
            // never stored, so the outcome cannot reveal whether it belongs to an account.
            var email = trustedEmail && !string.IsNullOrWhiteSpace(providerResult.Email) ? providerResult.Email : null;
            var existingEmailUser = email == null ? null : await _emailManager.FindByEmailAsync(email);
            cancellationToken.ThrowIfCancellationRequested();

            return existingEmailUser != null
                ? await LinkExistingAccountAsync(existingEmailUser, loginInfo)
                : await CreateAccountAsync(provider.Provider, providerResult, loginInfo, email, trustedEmail);
        }

        private async Task<Result<TUser>> LinkExistingAccountAsync(TUser existing, UserLoginInfo loginInfo) {
            var wasConfirmed = existing.EmailConfirmed;
            if(!wasConfirmed) {
                // The account was registered with this email but the email was never verified, so whoever
                // registered it may not own the mailbox and may know its password. Make the account safe
                // before attaching the verified identity. Each step leaves the account safe if a later
                // one fails, and a retry of the same login repeats them.
                if(_passwordManager == null)
                    return ResolveFailed();
                var removed = await _passwordManager.RemovePasswordAsync(existing);
                if(removed?.Succeeded != true)
                    return ResolveFailed();
                await RevokeSessionsAsync(existing);
            }

            var added = await _loginManager.AddLoginAsync(existing, loginInfo);
            if(added?.Succeeded != true)
                return ResolveFailed();

            if(!wasConfirmed) {
                existing.EmailConfirmed = true;
                var updated = await _userManager.UpdateAsync(existing);
                if(updated?.Succeeded != true) {
                    existing.EmailConfirmed = false;
                    // The link is complete and the account no longer has a password. Keep both so the
                    // same trusted login can be retried instead of racing a concurrent login.
                    return ResolveFailed();
                }
            }

            return new Result<TUser>(existing);
        }

        private async Task<Result<TUser>> CreateAccountAsync(string providerName,
                                                             ExternalLoginProviderResult<TUser> providerResult,
                                                             UserLoginInfo loginInfo,
                                                             string trustedEmail,
                                                             bool trusted) {
            var user = providerResult.User;
            if(trustedEmail == null) {
                // Mappers commonly copy the claim into Email and UserName. An untrusted claim is not stored.
                if(string.Equals(user.UserName, providerResult.Email, StringComparison.OrdinalIgnoreCase))
                    user.UserName = null;
                user.Email = null;
            } else if(string.IsNullOrWhiteSpace(user.Email)) {
                user.Email = trustedEmail;
            }

            if(string.IsNullOrWhiteSpace(user.UserName))
                user.UserName = trustedEmail ?? $"{providerName}_{loginInfo.ProviderKey}";
            user.EmailConfirmed = trusted && trustedEmail != null;

            var created = await _userManager.CreateAsync(user);
            if(created?.Succeeded != true)
                return ResolveFailed();

            var added = await _loginManager.AddLoginAsync(user, loginInfo);
            if(added?.Succeeded != true) {
                await TryDeleteAsync(user);
                return ResolveFailed();
            }

            return new Result<TUser>(user);
        }

        /// <summary>
        /// Removes the account created by the current operation after its login could not be attached.
        /// Identity's delete is guarded by the concurrency stamp, so an account that something else has
        /// already modified is left in place.
        /// </summary>
        private async Task TryDeleteAsync(TUser user) {
            try {
                var deleted = await _userManager.DeleteAsync(user);
                if(deleted?.Succeeded != true)
                    _logger?.LogWarning("Removing an account whose external login could not be attached did not succeed.");
            } catch(Exception exception) when(exception is not OperationCanceledException) {
                _logger?.LogWarning("Removing an account whose external login could not be attached failed. Exception type: {ExceptionType}.",
                    exception.GetType().FullName);
            }
        }

        private async Task RevokeSessionsAsync(TUser user) {
            if(_refreshTokenService != null)
                await _refreshTokenService.RevokeAllAsync(user.Id, CancellationToken.None);
        }

        private IExternalLoginProvider<TUser> FindProvider(string providerName) =>
            _providers.FirstOrDefault(provider => SameProvider(provider.Provider, providerName));

        private static bool SameProvider(string left, string right) =>
            string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

        private static Result<TUser> ResolveFailed() =>
            new(ResultCode.BadRequest, Result.CreateErrors(GenericFailureCode, GenericFailureDescription));

    }
}
