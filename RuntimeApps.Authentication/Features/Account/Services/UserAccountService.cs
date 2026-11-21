using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Features.Account.Services {
    public class UserAccountService<TUser, TKey>: IUserAccountService<TUser>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey> {
        private readonly IUserManager<TUser> _userManager;
        private readonly IUserLoginManager<TUser> _loginManager;
        private readonly IUserEmailManager<TUser> _emailManager;
        private readonly ISignInManager<TUser> _signInManager;
        private readonly Microsoft.AspNetCore.Http.IHttpContextAccessor _contextAccessor;
        private readonly IEnumerable<IExternalLoginProvider<TUser>> _externalLoginProviders;
        private readonly IExternalLoginEmailTrustPolicy<TUser> _externalLoginEmailTrustPolicy;
        private readonly VerificationOptions _verificationOptions;
        private readonly IVerificationWorkflowService<TUser, TKey> _verificationWorkflow;
        private readonly IAuthenticationSessionIssuer<TUser> _sessionIssuer;

        // Preserve the original public constructor for existing compiled consumers.
        public UserAccountService(IUserManager<TUser> userManager,
                                  ISignInManager<TUser> signInManager,
                                  IEnumerable<IExternalLoginProvider<TUser>> externalLoginProviders,
                                  IAuthenticationHandlerProvider authenticationHandlerProvider,
                                  IHttpContextAccessor contextAccessor,
                                  IUserClaimsPrincipalFactory<TUser> userClaimsPrincipalFactory,
                                  IAuthenticationSchemeProvider authenticationSchemeProvider,
                                  IJwtProvider<TUser> jwtUtils = null)
            : this(userManager, signInManager, externalLoginProviders, authenticationHandlerProvider,
                   contextAccessor, userClaimsPrincipalFactory, authenticationSchemeProvider,
                   jwtUtils, null, null, null, null, null, null, null) {
        }

        public UserAccountService(IUserManager<TUser> userManager,
                                  ISignInManager<TUser> signInManager,
                                  IEnumerable<IExternalLoginProvider<TUser>> externalLoginProviders,
                                  IAuthenticationHandlerProvider authenticationHandlerProvider,
                                  IHttpContextAccessor contextAccessor,
                                  IUserClaimsPrincipalFactory<TUser> userClaimsPrincipalFactory,
                                  IAuthenticationSchemeProvider authenticationSchemeProvider,
                                  IJwtProvider<TUser> jwtUtils = null,
                                  IRefreshTokenService<TKey> refreshTokenService = null,
                                  IOptions<RefreshTokenOptions> refreshTokenOptions = null,
                                  IExternalLoginEmailTrustPolicy<TUser> externalLoginEmailTrustPolicy = null,
                                  IOptions<VerificationOptions> verificationOptions = null,
                                  IVerificationWorkflowService<TUser, TKey> verificationWorkflow = null,
                                  IUserLoginManager<TUser> loginManager = null,
                                  IUserEmailManager<TUser> emailManager = null,
                                  IAuthenticationSessionIssuer<TUser> sessionIssuer = null) {
            _userManager = userManager;
            _loginManager = loginManager ?? userManager as IUserLoginManager<TUser>;
            _emailManager = emailManager ?? userManager as IUserEmailManager<TUser>;
            _signInManager = signInManager;
            _externalLoginProviders = externalLoginProviders;
            _contextAccessor = contextAccessor;
            _externalLoginEmailTrustPolicy = externalLoginEmailTrustPolicy;
            _verificationOptions = verificationOptions?.Value ?? new VerificationOptions();
            _verificationWorkflow = verificationWorkflow;
            _sessionIssuer = sessionIssuer;
        }

        public virtual async Task<Result<TUser, Token>> ExternalLoginAsync(string providerName, string token, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            var provider = _externalLoginProviders.FirstOrDefault(p => string.Equals(p.Provider, providerName, StringComparison.OrdinalIgnoreCase));
            if(provider == null)
                return ExternalAuthenticationFailed();

            var providerResult = await provider.ValidateAsync(token, cancellationToken);
            if(providerResult?.LoginInfo == null || providerResult.User == null)
                return ExternalAuthenticationFailed();

            cancellationToken.ThrowIfCancellationRequested();
            var loginInfo = providerResult.LoginInfo;
            // Identity manager/store APIs used below have no CancellationToken overloads.
            var user = await _loginManager.FindByLoginAsync(loginInfo.LoginProvider, loginInfo.ProviderKey);
            cancellationToken.ThrowIfCancellationRequested();
            if(user == null) {
                var trustedEmail = _externalLoginEmailTrustPolicy?.IsEmailTrusted(provider.Provider, providerResult) == true;
                // Do not look up an untrusted email and branch on whether it belongs to an
                // account. Reject the same untrusted identity before either account path.
                if((!string.IsNullOrWhiteSpace(providerResult.Email) && !trustedEmail) ||
                   (_verificationOptions.RequireEmailVerificationForExternalLogins && !trustedEmail))
                    return ExternalAuthenticationFailed();

                var existingEmailUser = string.IsNullOrWhiteSpace(providerResult.Email)
                    ? null
                    : await _emailManager.FindByEmailAsync(providerResult.Email);
                cancellationToken.ThrowIfCancellationRequested();

                if(existingEmailUser != null) {
                    user = existingEmailUser;
                    var wasEmailConfirmed = user.EmailConfirmed;
                    // Link first. If the subsequent confirmation update fails, undo the link.
                    var addLoginResult = await _loginManager.AddLoginAsync(user, loginInfo);
                    if(!addLoginResult.Succeeded)
                        return ExternalAuthenticationFailed();

                    if(!wasEmailConfirmed) {
                        user.EmailConfirmed = true;
                        var updateResult = await _userManager.UpdateAsync(user);
                        if(!updateResult.Succeeded) {
                            user.EmailConfirmed = wasEmailConfirmed;
                            // The link is a complete, trusted Identity association. Keep it
                            // retryable if confirmation persistence fails instead of racing a
                            // concurrent login by compensating with RemoveLoginAsync.
                            return ExternalAuthenticationFailed();
                        }
                    }
                } else {
                    user = providerResult.User;
                    if(string.IsNullOrWhiteSpace(user.Email))
                        user.Email = providerResult.Email;
                    if(string.IsNullOrWhiteSpace(user.UserName))
                        user.UserName = !string.IsNullOrWhiteSpace(providerResult.Email)
                            ? providerResult.Email
                            : $"{provider.Provider}_{loginInfo.ProviderKey}";
                    user.EmailConfirmed = trustedEmail;

                    var createResult = await _userManager.CreateAsync(user);
                    if(!createResult.Succeeded)
                        return ExternalAuthenticationFailed();

                    var addLoginResult = await _loginManager.AddLoginAsync(user, loginInfo);
                    if(!addLoginResult.Succeeded)
                        // Identity exposes no transaction spanning user creation and external
                        // login linking. Leave the valid account in place: the same trusted
                        // provider retry can find it and attach the login. Deleting it here
                        // could race another operation that has already started using it.
                        return ExternalAuthenticationFailed();
                }
            }

            if(user == null)
                return ExternalAuthenticationFailed();

            // The non-cancellable Identity writes above are now consistent. Honor cancellation
            // before sending verification or issuing an authentication session.
            cancellationToken.ThrowIfCancellationRequested();

            if(_verificationOptions.RequireEmailVerificationForExternalLogins && !user.EmailConfirmed) {
                if(string.IsNullOrWhiteSpace(user.Email) || _verificationWorkflow == null)
                    return ExternalAuthenticationFailed();

                var verification = await _verificationWorkflow.StartAsync(
                    user, VerificationPurpose.Registration, VerificationChannel.Email, user.Email, cancellationToken: cancellationToken);
                if(!verification.Succeeded)
                    return ExternalAuthenticationFailed();

                return new Result<TUser, Token>(user, new Token {
                    VerificationRequired = true,
                    VerificationHandle = verification.VerificationHandle,
                    VerificationExpiresAt = verification.ExpiresAt
                });
            }

            return await GenerateTokenAsync(user, cancellationToken);
        }

        private static Result<TUser, Token> ExternalAuthenticationFailed() =>
            new(ResultCode.BadRequest, Result.CreateErrors(
                "ExternalAuthenticationFailed", "External authentication could not be completed."));

        /// <remarks>Identity lookup and password sign-in abstractions in ASP.NET Core do not expose cancellation overloads.</remarks>
        public virtual async Task<Result<TUser, Token>> LoginAsync(string userName, string password, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            var userInfo = await _userManager.FindByNameAsync(userName);
            cancellationToken.ThrowIfCancellationRequested();
            if(userInfo == null || !userInfo.EmailConfirmed)
                return GetIdentityError(SignInResult.Failed);

            var signInResult = await _signInManager.PasswordSignInAsync(userInfo, password, false, true);
            cancellationToken.ThrowIfCancellationRequested();
            if(!signInResult.Succeeded)
                return GetIdentityError(signInResult);

            return await GenerateTokenAsync(userInfo, cancellationToken);
        }

        public virtual Task<Result<TUser, Token>> CompleteRegistrationAsync(TUser user, CancellationToken cancellationToken = default) {
            if(user == null || !user.EmailConfirmed)
                return Task.FromResult(new Result<TUser, Token>(
                    ResultCode.Forbidden,
                    Result.CreateErrors("EmailNotConfirmed", "The account must complete email verification before registration can be completed.")));

            return GenerateTokenAsync(user, cancellationToken);
        }

        protected virtual Result<TUser, Token> GetIdentityError(SignInResult signInResult) {
            if(signInResult.RequiresTwoFactor)
                return new Result<TUser, Token>(ResultCode.Accepted, Result.CreateErrors("TwoFactorRequired", "A second authentication step is required."));

            // Keep all credential-state failures identical at the public boundary.
            return new Result<TUser, Token>(ResultCode.BadRequest,
                Result.CreateErrors("AuthenticationFailed", "The username or password is incorrect."));
        }

        protected virtual async Task<Result<TUser, Token>> GenerateTokenAsync(TUser user, CancellationToken cancellationToken = default) {
            if(_sessionIssuer == null)
                throw new InvalidOperationException("An authentication session issuer must be explicitly registered.");
            cancellationToken.ThrowIfCancellationRequested();
            var token = await _sessionIssuer.IssueAsync(user, cancellationToken);
            return new Result<TUser, Token>(user, token);
        }

    }
}
