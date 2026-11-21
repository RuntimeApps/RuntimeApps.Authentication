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

        public virtual async Task<Result<TUser, Token>> ExternalLoginAsync(string providerName, string token) {
            var provider = _externalLoginProviders.FirstOrDefault(p => p.Provider.Equals(providerName, StringComparison.OrdinalIgnoreCase));
            if(provider == null)
                return new Result<TUser, Token>(ResultCode.BadRequest, Result.CreateErrors("Unknown provider", "Provider is not added to system"));

            var providerResult = await provider.ValidateAsync(token);
            if(providerResult?.LoginInfo == null || providerResult.User == null)
                return new Result<TUser, Token>(ResultCode.BadRequest, Result.CreateErrors("Invalid token", "Invalid External Authentication."));

            var loginInfo = providerResult.LoginInfo;
            var user = await _loginManager.FindByLoginAsync(loginInfo.LoginProvider, loginInfo.ProviderKey);
            if(user == null) {
                var trustedEmail = _externalLoginEmailTrustPolicy?.IsEmailTrusted(provider.Provider, providerResult) == true;
                var existingEmailUser = string.IsNullOrWhiteSpace(providerResult.Email)
                    ? null
                    : await _emailManager.FindByEmailAsync(providerResult.Email);

                if(existingEmailUser != null) {
                    // Never link an external identity to an existing account based on an unverified email.
                    if(!trustedEmail)
                        return new Result<TUser, Token>(
                            ResultCode.Conflict,
                            Result.CreateErrors("ExternalAccountLinkRequired", "Sign in to the existing account before linking this external provider."));

                    user = existingEmailUser;
                    if(!user.EmailConfirmed) {
                        user.EmailConfirmed = true;
                        var updateResult = await _userManager.UpdateAsync(user);
                        if(!updateResult.Succeeded)
                            return new Result<TUser, Token>(ResultCode.BadRequest, updateResult.Errors);
                    }

                    var addLoginResult = await _loginManager.AddLoginAsync(user, loginInfo);
                    if(!addLoginResult.Succeeded)
                        return new Result<TUser, Token>(ResultCode.BadRequest, addLoginResult.Errors);
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
                        return new Result<TUser, Token>(ResultCode.BadRequest, createResult.Errors);

                    var addLoginResult = await _loginManager.AddLoginAsync(user, loginInfo);
                    if(!addLoginResult.Succeeded)
                        return new Result<TUser, Token>(ResultCode.BadRequest, addLoginResult.Errors);
                }
            }

            if(user == null)
                return new Result<TUser, Token>(ResultCode.BadRequest, Result.CreateErrors("Add_Error", "User cannot added"));

            if(_verificationOptions.RequireEmailVerificationForExternalLogins && !user.EmailConfirmed) {
                if(string.IsNullOrWhiteSpace(user.Email) || _verificationWorkflow == null)
                    return new Result<TUser, Token>(
                        ResultCode.Forbidden,
                        Result.CreateErrors("EmailVerificationRequired", "Email verification is required but no verified email address or verification workflow is available."));

                var verification = await _verificationWorkflow.StartAsync(
                    user, VerificationPurpose.Registration, VerificationChannel.Email, user.Email);
                if(!verification.Succeeded)
                    return new Result<TUser, Token>(
                        ResultCode.Forbidden,
                        Result.CreateErrors(verification.ErrorCode, verification.ErrorDescription));

                return new Result<TUser, Token>(user, new Token {
                    VerificationRequired = true,
                    VerificationHandle = verification.VerificationHandle,
                    VerificationExpiresAt = verification.ExpiresAt
                });
            }

            // A validated provider identity is only the first factor. Never issue a normal
            // application session for an account that requires Identity two-factor auth.
            if(user.TwoFactorEnabled) {
                var challenge = await _signInManager.CreateTwoFactorChallengeAsync(user);
                if(!challenge.RequiresTwoFactor)
                    return GetIdentityError(challenge);
                return new Result<TUser, Token>(ResultCode.Accepted,
                    Result.CreateErrors("TwoFactorRequired", "Two factor authentication required"));
            }

            return await GenerateTokenAsync(user);
        }

        public virtual async Task<Result<TUser, Token>> LoginAsync(string userName, string password) {
            var userInfo = await _userManager.FindByNameAsync(userName);
            if(userInfo == null || !userInfo.EmailConfirmed)
                return GetIdentityError(SignInResult.Failed);

            var signInResult = await _signInManager.PasswordSignInAsync(userInfo, password, false, true);
            if(!signInResult.Succeeded)
                return GetIdentityError(signInResult);

            return await GenerateTokenAsync(userInfo);
        }

        public virtual Task<Result<TUser, Token>> CompleteRegistrationAsync(TUser user) {
            if(user == null || !user.EmailConfirmed)
                return Task.FromResult(new Result<TUser, Token>(
                    ResultCode.Forbidden,
                    Result.CreateErrors("EmailNotConfirmed", "The account must complete email verification before registration can be completed.")));

            return GenerateTokenAsync(user);
        }

        protected virtual Result<TUser, Token> GetIdentityError(SignInResult signInResult) {
            ResultCode code = ResultCode.BadRequest;
            var description = "Username or password is incorrect";
            if(signInResult.IsNotAllowed) {
                description = "You are not allowed to login";
                code = ResultCode.Forbidden;
            }
            else if(signInResult.IsLockedOut) {
                description = "You are locked out";
                code = ResultCode.Conflict;
            }
            else if(signInResult.RequiresTwoFactor) {
                description = "Two factor authentication required";
                code = ResultCode.Accepted;
            }
            return new Result<TUser, Token>(code, Result.CreateErrors(signInResult.ToString(), description));
        }

        protected virtual async Task<Result<TUser, Token>> GenerateTokenAsync(TUser user) {
            if(_sessionIssuer == null)
                throw new InvalidOperationException("An authentication session issuer must be explicitly registered.");
            var token = await _sessionIssuer.IssueAsync(user, _contextAccessor.HttpContext?.RequestAborted ?? CancellationToken.None);
            return new Result<TUser, Token>(user, token);
        }

    }
}
