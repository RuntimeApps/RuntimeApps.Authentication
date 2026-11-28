using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Services;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
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
        private readonly ISignInManager<TUser> _signInManager;
        private readonly Microsoft.AspNetCore.Http.IHttpContextAccessor _contextAccessor;
        private readonly IExternalLoginService<TUser> _externalLoginService;
        private readonly VerificationOptions _verificationOptions;
        private readonly IVerificationWorkflowService<TUser, TKey> _verificationWorkflow;
        private readonly IAuthenticationSessionIssuer<TUser> _sessionIssuer;
        private readonly ITwoFactorLoginService<TUser> _twoFactorLogin;

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
                   jwtUtils, null, null, null, null, null, null, null, null) {
        }

        // Preserve the previous public constructor signature for existing compiled consumers. It has no
        // optional parameters so that calls with fewer arguments bind to the constructor below, which
        // is also the one dependency injection selects.
        public UserAccountService(IUserManager<TUser> userManager,
                                  ISignInManager<TUser> signInManager,
                                  IEnumerable<IExternalLoginProvider<TUser>> externalLoginProviders,
                                  IAuthenticationHandlerProvider authenticationHandlerProvider,
                                  IHttpContextAccessor contextAccessor,
                                  IUserClaimsPrincipalFactory<TUser> userClaimsPrincipalFactory,
                                  IAuthenticationSchemeProvider authenticationSchemeProvider,
                                  IJwtProvider<TUser> jwtUtils,
                                  IRefreshTokenService<TKey> refreshTokenService,
                                  IOptions<RefreshTokenOptions> refreshTokenOptions,
                                  IExternalLoginEmailTrustPolicy<TUser> externalLoginEmailTrustPolicy,
                                  IOptions<VerificationOptions> verificationOptions,
                                  IVerificationWorkflowService<TUser, TKey> verificationWorkflow,
                                  IUserLoginManager<TUser> loginManager,
                                  IUserEmailManager<TUser> emailManager,
                                  IAuthenticationSessionIssuer<TUser> sessionIssuer)
            : this(userManager, signInManager, externalLoginProviders, authenticationHandlerProvider,
                   contextAccessor, userClaimsPrincipalFactory, authenticationSchemeProvider,
                   jwtUtils, refreshTokenService, refreshTokenOptions, externalLoginEmailTrustPolicy,
                   verificationOptions, verificationWorkflow, loginManager, emailManager, sessionIssuer,
                   (IExternalLoginService<TUser>)null) {
        }

        // Preserve the previous public constructor signature. It has no optional parameters so that calls
        // with fewer arguments bind to the constructor below, which is also the one dependency injection selects.
        public UserAccountService(IUserManager<TUser> userManager,
                                  ISignInManager<TUser> signInManager,
                                  IEnumerable<IExternalLoginProvider<TUser>> externalLoginProviders,
                                  IAuthenticationHandlerProvider authenticationHandlerProvider,
                                  IHttpContextAccessor contextAccessor,
                                  IUserClaimsPrincipalFactory<TUser> userClaimsPrincipalFactory,
                                  IAuthenticationSchemeProvider authenticationSchemeProvider,
                                  IJwtProvider<TUser> jwtUtils,
                                  IRefreshTokenService<TKey> refreshTokenService,
                                  IOptions<RefreshTokenOptions> refreshTokenOptions,
                                  IExternalLoginEmailTrustPolicy<TUser> externalLoginEmailTrustPolicy,
                                  IOptions<VerificationOptions> verificationOptions,
                                  IVerificationWorkflowService<TUser, TKey> verificationWorkflow,
                                  IUserLoginManager<TUser> loginManager,
                                  IUserEmailManager<TUser> emailManager,
                                  IAuthenticationSessionIssuer<TUser> sessionIssuer,
                                  IExternalLoginService<TUser> externalLoginService)
            : this(userManager, signInManager, externalLoginProviders, authenticationHandlerProvider,
                   contextAccessor, userClaimsPrincipalFactory, authenticationSchemeProvider,
                   jwtUtils, refreshTokenService, refreshTokenOptions, externalLoginEmailTrustPolicy,
                   verificationOptions, verificationWorkflow, loginManager, emailManager, sessionIssuer,
                   externalLoginService, (ITwoFactorLoginService<TUser>)null) {
        }

        /// <param name="externalLoginService">
        /// Resolves accounts for external logins. When omitted, a default service is composed from the
        /// other dependencies, so existing constructors and registrations keep working.
        /// </param>
        /// <param name="twoFactorLogin">
        /// Starts the second login step. When omitted (two-factor authentication is not registered) the
        /// behavior is unchanged: a sign-in that requires two factors is reported without a challenge.
        /// </param>
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
                                  IAuthenticationSessionIssuer<TUser> sessionIssuer = null,
                                  IExternalLoginService<TUser> externalLoginService = null,
                                  ITwoFactorLoginService<TUser> twoFactorLogin = null) {
            _twoFactorLogin = twoFactorLogin;
            _userManager = userManager;
            _signInManager = signInManager;
            _contextAccessor = contextAccessor;
            _verificationOptions = verificationOptions?.Value ?? new VerificationOptions();
            _verificationWorkflow = verificationWorkflow;
            _sessionIssuer = sessionIssuer;
            _externalLoginService = externalLoginService ?? new ExternalLoginService<TUser, TKey>(
                externalLoginProviders,
                userManager,
                loginManager ?? userManager as IUserLoginManager<TUser>,
                emailManager ?? userManager as IUserEmailManager<TUser>,
                userManager as IUserPasswordManager<TUser>,
                signInManager,
                externalLoginEmailTrustPolicy,
                verificationOptions,
                refreshTokenService);
        }

        public virtual async Task<Result<TUser, Token>> ExternalLoginAsync(string providerName, string token, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            var resolved = await _externalLoginService.ResolveLoginAsync(providerName, token, cancellationToken);
            if(!resolved.Succeeded || resolved.Data == null)
                return ExternalAuthenticationFailed();
            var user = resolved.Data;

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

            // The provider (and the email-verification gate above) passed. Users with two-factor enabled still
            // answer the local second step unless the application chose to trust the provider.
            if(_twoFactorLogin != null) {
                var start = await _twoFactorLogin.BeginExternalAsync(user, cancellationToken);
                if(!start.SignInAllowed)
                    return CreateTwoFactorRequired(start);
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
            if(signInResult.RequiresTwoFactor && _twoFactorLogin != null)
                return await BeginTwoFactorAsync(userInfo, cancellationToken);
            if(!signInResult.Succeeded)
                return GetIdentityError(signInResult);

            return await GenerateTokenAsync(userInfo, cancellationToken);
        }

        /// <summary>
        /// The password was correct but a second step is required. No session is issued unless the application
        /// explicitly allows users without an enrolled method to sign in.
        /// </summary>
        protected virtual async Task<Result<TUser, Token>> BeginTwoFactorAsync(TUser user, CancellationToken cancellationToken = default) {
            var start = await _twoFactorLogin.BeginAsync(user, cancellationToken);
            if(start.SignInAllowed) {
                // Identity does not reset the failed-access count while a second step is pending.
                if(_userManager is IUserLockoutManager<TUser> lockout)
                    await lockout.ResetAccessFailedCountAsync(user);
                return await GenerateTokenAsync(user, cancellationToken);
            }

            return CreateTwoFactorRequired(start);
        }

        private static Result<TUser, Token> CreateTwoFactorRequired(TwoFactorLoginStart start) =>
            new(ResultCode.Accepted, Result.CreateErrors("TwoFactorRequired", "A second authentication step is required.")) {
                Meta = new Token {
                    TwoFactorChallenge = start.Challenge,
                    TwoFactorExpiresAt = start.ExpiresAt,
                    TwoFactorMethods = start.Methods
                }
            };

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
