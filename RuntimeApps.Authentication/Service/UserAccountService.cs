using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
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

        public UserAccountService(IUserManager<TUser> userManager,
                                  ISignInManager<TUser> signInManager,
                                  IEnumerable<IExternalLoginProvider<TUser>> externalLoginProviders,
                                  IAuthenticationHandlerProvider authenticationHandlerProvider,
                                  IHttpContextAccessor contextAccessor,
                                  IUserClaimsPrincipalFactory<TUser> userClaimsPrincipalFactory,
                                  IAuthenticationSchemeProvider authenticationSchemeProvider,
                                  IJwtProvider<TUser> jwtUtils = null) {
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtUtils = jwtUtils;
            _externalLoginProviders = externalLoginProviders;
            _authenticationHandlerProvider = authenticationHandlerProvider;
            _contextAccessor = contextAccessor;
            _userClaimsPrincipalFactory = userClaimsPrincipalFactory;
            _authenticationSchemeProvider = authenticationSchemeProvider;
        }

        public virtual async Task<Result<TUser, Token>> ExternalLoginAsync(string providerName, string token) {
            var provider = _externalLoginProviders.FirstOrDefault(p => p.Provider.Equals(providerName, StringComparison.OrdinalIgnoreCase));
            if(provider == null)
                return new Result<TUser, Token>(ResultCode.BadRequest, Result.CreateErrors("Unknown provider", "Provider is not added to system"));

            (TUser userInfo, UserLoginInfo loginInfo) = await provider.ValidateAsync(token);
            if(loginInfo == null)
                return new Result<TUser, Token>(ResultCode.BadRequest, Result.CreateErrors("Invalid token", "Invalid External Authentication."));

            var user = await _userManager.FindByLoginAsync(loginInfo.LoginProvider, loginInfo.ProviderKey);
            if(user == null) {
                user = await _userManager.FindByEmailAsync(userInfo.Email);
                if(user == null) {
                    user = userInfo;

                    var createResult = await _userManager.CreateAsync(user);
                    if(!createResult.Succeeded)
                        return new Result<TUser, Token>(ResultCode.BadRequest, createResult.Errors);

                    var addLoginResult = await _userManager.AddLoginAsync(user, loginInfo);
                    if(!addLoginResult.Succeeded)
                        return new Result<TUser, Token>(ResultCode.BadRequest, addLoginResult.Errors);
                }
                else {
                    var addLoginResult = await _userManager.AddLoginAsync(user, loginInfo);
                    if(!addLoginResult.Succeeded)
                        return new Result<TUser, Token>(ResultCode.BadRequest, addLoginResult.Errors);
                }
            }

            if(user == null)
                return new Result<TUser, Token>(ResultCode.BadRequest, Result.CreateErrors("Add_Error", "User cannot added"));

            return await GenerateTokenAsync(user);
        }

        public virtual async Task<Result<TUser, Token>> LoginAsync(string userName, string password) {
            var userInfo = await _userManager.FindByNameAsync(userName);
            if(userInfo == null)
                return GetIdentityError(SignInResult.Failed);

            var signInResult = await _signInManager.PasswordSignInAsync(userInfo, password, true, false);
            if(!signInResult.Succeeded) {
                return GetIdentityError(signInResult);
            }

            return await GenerateTokenAsync(userInfo);
        }

        public virtual async Task<Result<TUser, Token>> RegisterAsync(TUser user, string password) {
            if(string.IsNullOrEmpty(user.UserName))
                user.UserName = user.Email;

            var createResult = await _userManager.CreateAsync(user, password);
            if(!createResult.Succeeded) {
                return new Result<TUser, Token>(ResultCode.BadRequest, createResult.Errors);
            }

            return await GenerateTokenAsync(user);
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
                return new Result<TUser, Token>(user, null);
            }

            var token = await _jwtUtils.GenerateTokenAsync(user);
            return new Result<TUser, Token>(user, token);
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
