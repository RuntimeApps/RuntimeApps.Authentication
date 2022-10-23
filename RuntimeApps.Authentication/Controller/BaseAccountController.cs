using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Controller {
    public abstract class BaseAccountController<TUser, TKey>: ControllerBase
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey> {
        private readonly IUserAccountService<TUser> _userAccountService;

        public BaseAccountController(IUserAccountService<TUser> userAccountService) {
            _userAccountService = userAccountService;
        }

        [HttpPost("login")]
        public virtual Task<Result<TUser, Token>> LoginUser([FromBody] UserLoginModel userLoginModel) {
            return _userAccountService.LoginAsync(userLoginModel.UserName, userLoginModel.Password);
        }

        [HttpPost("register")]
        public virtual Task<Result<TUser, Token>> RegisterUser([FromBody] RegisterUserModel<TUser> user) {
            return _userAccountService.RegisterAsync(user.UserInfo, user.Password);
        }

        [HttpPost("login/external")]
        public virtual Task<Result<TUser, Token>> ExternalLogin([FromBody] ExternalAuthModel request) {
            return _userAccountService.ExternalLoginAsync(request.Provider, request.Token);
        }

    }
}
