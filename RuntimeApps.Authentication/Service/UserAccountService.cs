using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Service {
    public class UserAccountService<TUser, TKey>: IUserAccountService<TUser>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey> {
        private readonly IUserManager<TUser> _userManager;
        private readonly IJwtProvider<TUser> _jwtUtils;
        private readonly IEnumerable<IExternalLoginProvider<TUser>> _externalLoginProviders;

        public UserAccountService(IUserManager<TUser> userManager,
                                  IJwtProvider<TUser> jwtUtils,
                                  IEnumerable<IExternalLoginProvider<TUser>> externalLoginProviders
            ) {
            _userManager = userManager;
            _jwtUtils = jwtUtils;
            _externalLoginProviders = externalLoginProviders;
        }

        public virtual async Task<Result<TUser, Token>> ExternalLoginAsync(string providerName, string token) {
            var provider = _externalLoginProviders.FirstOrDefault(p => p.Provider.Equals(providerName, StringComparison.OrdinalIgnoreCase));
            if(provider == null)
                return new Result<TUser, Token>(ResultCode.BadRequest, "Unknown provider");

            (TUser userInfo, UserLoginInfo loginInfo) = await provider.ValidateAsync(token);
            if(loginInfo == null)
                return new Result<TUser, Token>(ResultCode.BadRequest, "Invalid External Authentication.");

            var user = await _userManager.FindByLoginAsync(loginInfo.LoginProvider, loginInfo.ProviderKey);
            if(user == null) {
                user = await _userManager.FindByEmailAsync(userInfo.Email);
                if(user == null) {
                    user = userInfo;
                    await _userManager.CreateAsync(user);
                    await _userManager.AddLoginAsync(user, loginInfo);
                }
                else {
                    await _userManager.AddLoginAsync(user, loginInfo);
                }
            }

            if(user == null)
                return new Result<TUser, Token>(ResultCode.BadRequest, "User cannot added");

            var authToken = _jwtUtils.GenerateToken(user);
            return new Result<TUser, Token>() {
                Data = user,
                Meta = authToken
            };
        }

        public virtual async Task<Result<TUser, Token>> LoginAsync(string userName, string password) {
            var userInfo = await _userManager.FindByNameAsync(userName);
            if(userInfo == null)
                return new Result<TUser, Token>(ResultCode.BadRequest, "Username or password is incorrect");

            var passwordMatch = await _userManager.CheckPasswordAsync(userInfo, password);
            if(!passwordMatch)
                return new Result<TUser, Token>(ResultCode.BadRequest, "Username or password is incorrect");

            var token = _jwtUtils.GenerateToken(userInfo);
            return new Result<TUser, Token>(userInfo, token);
        }

        public virtual async Task<Result<TUser, Token>> RegisterAsync(TUser user, string password) {
            if(string.IsNullOrEmpty(user.UserName))
                user.UserName = user.Email;

            var userInfo = await _userManager.FindByNameAsync(user.UserName);
            if(userInfo != null) {
                return new Result<TUser, Token>(ResultCode.BadRequest, "This user exists");
            }

            var createResult = await _userManager.CreateAsync(user, password);
            if(!createResult.Succeeded) {
                return new Result<TUser, Token>(ResultCode.BadRequest, createResult.Errors?.FirstOrDefault()?.Description);
            }

            var token = _jwtUtils.GenerateToken(user);
            return new Result<TUser, Token>(user, token);
        }
    }
}
