using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Service {
    public class UserAccountService<TUser, TKey>: IUserAccountService<TUser>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey> {
        private readonly IUserManager<TUser> _userManager;
        private readonly ISignInManager<TUser> _signInManager;
        private readonly IJwtProvider<TUser> _jwtUtils;
        private readonly IAuthenticationSchemeProvider _authenticationSchemeProvider;
        private readonly IAuthenticationHandlerProvider _authenticationHandlerProvider;
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IUserClaimsPrincipalFactory<TUser> _userClaimsPrincipalFactory;
        private readonly IEnumerable<IExternalLoginProvider<TUser>> _externalLoginProviders;
        private readonly IRefreshTokenService<TKey> _refreshTokenService;
        private readonly RefreshTokenOptions _refreshTokenOptions;
        private readonly IExternalLoginEmailTrustPolicy<TUser> _externalLoginEmailTrustPolicy;
        private readonly VerificationOptions _verificationOptions;
        private readonly IVerificationWorkflowService<TUser, TKey> _verificationWorkflow;

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
                   jwtUtils, null, null, null, null, null) {
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
                                  IVerificationWorkflowService<TUser, TKey> verificationWorkflow = null) {
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtUtils = jwtUtils;
            _externalLoginProviders = externalLoginProviders;
            _authenticationHandlerProvider = authenticationHandlerProvider;
            _contextAccessor = contextAccessor;
            _userClaimsPrincipalFactory = userClaimsPrincipalFactory;
            _authenticationSchemeProvider = authenticationSchemeProvider;
            _refreshTokenService = refreshTokenService;
            _refreshTokenOptions = refreshTokenOptions?.Value ?? new RefreshTokenOptions();
            _externalLoginEmailTrustPolicy = externalLoginEmailTrustPolicy;
            _verificationOptions = verificationOptions?.Value ?? new VerificationOptions();
            _verificationWorkflow = verificationWorkflow;
        }

        public virtual async Task<Result<TUser, Token>> ExternalLoginAsync(string providerName, string token) {
            var provider = _externalLoginProviders.FirstOrDefault(p => p.Provider.Equals(providerName, StringComparison.OrdinalIgnoreCase));
            if(provider == null)
                return new Result<TUser, Token>(ResultCode.BadRequest, Result.CreateErrors("Unknown provider", "Provider is not added to system"));

            var providerResult = await provider.ValidateAsync(token);
            if(providerResult?.LoginInfo == null || providerResult.User == null)
                return new Result<TUser, Token>(ResultCode.BadRequest, Result.CreateErrors("Invalid token", "Invalid External Authentication."));

            var loginInfo = providerResult.LoginInfo;
            var user = await _userManager.FindByLoginAsync(loginInfo.LoginProvider, loginInfo.ProviderKey);
            if(user == null) {
                var trustedEmail = _externalLoginEmailTrustPolicy?.IsEmailTrusted(provider.Provider, providerResult) == true;
                var existingEmailUser = string.IsNullOrWhiteSpace(providerResult.Email)
                    ? null
                    : await _userManager.FindByEmailAsync(providerResult.Email);

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

                    var addLoginResult = await _userManager.AddLoginAsync(user, loginInfo);
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

                    var addLoginResult = await _userManager.AddLoginAsync(user, loginInfo);
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

            return await GenerateTokenAsync(user);
        }

        public virtual async Task<Result<TUser, Token>> LoginAsync(string userName, string password) {
            var userInfo = await _userManager.FindByNameAsync(userName);
            if(userInfo == null || !userInfo.EmailConfirmed)
                return GetIdentityError(SignInResult.Failed);

            var signInResult = await _signInManager.PasswordSignInAsync(userInfo, password, true, false);
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
            bool hasHandler = await HasHandlerAsync();

            if(hasHandler) {
                var claims = await _userClaimsPrincipalFactory.CreateAsync(user);
                await _contextAccessor.HttpContext.SignInAsync(claims);

                if(_refreshTokenService != null) {
                    var httpContext = _contextAccessor.HttpContext;
                    var cancellationToken = httpContext?.RequestAborted ?? CancellationToken.None;
                    var existingRefreshToken = httpContext?.Request.Cookies[_refreshTokenOptions.CookieName];
                    if(!string.IsNullOrEmpty(existingRefreshToken))
                        await _refreshTokenService.RevokeAsync(existingRefreshToken, cancellationToken);

                    var refreshSession = await _refreshTokenService.CreateSessionAsync(
                        user.Id, cancellationToken: cancellationToken);
                    AppendRefreshCookie(refreshSession.RefreshToken, refreshSession.ExpiresAt);
                }
                return new Result<TUser, Token>(user, null);
            }

            var token = await _jwtUtils.GenerateTokenAsync(user);
            if(_refreshTokenService != null) {
                var cancellationToken = _contextAccessor.HttpContext?.RequestAborted ?? CancellationToken.None;
                var refreshSession = await _refreshTokenService.CreateSessionAsync(
                    user.Id, cancellationToken: cancellationToken);
                token.RefreshToken = refreshSession.RefreshToken;
                token.RefreshTokenExpireDate = refreshSession.ExpiresAt;
                token.SessionId = refreshSession.SessionId;
            }
            return new Result<TUser, Token>(user, token);
        }

        private void AppendRefreshCookie(string refreshToken, DateTimeOffset expiresAt) {
            var context = _contextAccessor.HttpContext;
            if(context == null)
                throw new InvalidOperationException("An HTTP context is required to issue a refresh-token cookie.");

            context.Response.Cookies.Append(_refreshTokenOptions.CookieName, refreshToken, new CookieOptions {
                HttpOnly = true,
                Secure = _refreshTokenOptions.CookieSecure,
                SameSite = _refreshTokenOptions.CookieSameSite,
                Path = _refreshTokenOptions.CookiePath,
                Expires = expiresAt
            });
        }

        private async Task<bool> HasHandlerAsync() {
            var defaultScheme = await _authenticationSchemeProvider.GetDefaultSignInSchemeAsync();
            if(defaultScheme?.Name == null)
                return false;

            var handler = await _authenticationHandlerProvider.GetHandlerAsync(_contextAccessor.HttpContext, defaultScheme.Name);
            if(handler == null)
                return false;
            return handler is IAuthenticationSignInHandler;
        }
    }
}