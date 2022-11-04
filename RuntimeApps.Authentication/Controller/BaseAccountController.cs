using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Controller {
    public abstract class BaseAccountController<TUser, TUserDto, TKey>: ControllerBase
        where TUser : IdentityUser<TKey>
        where TUserDto : class
        where TKey : IEquatable<TKey> {
        private readonly IUserAccountService<TUser> _userAccountService;
        private readonly IMapper _mapper;

        public BaseAccountController(IUserAccountService<TUser> userAccountService, IMapper mapper) {
            _userAccountService = userAccountService;
            _mapper = mapper;
        }

        [HttpPost("login")]
        
        public virtual async Task<IActionResult> LoginUser([FromBody] UserLoginModel userLoginModel) {
            var result = await _userAccountService.LoginAsync(userLoginModel.UserName, userLoginModel.Password);
            return MapResponse(result);
        }

        [HttpPost("register")]
        public virtual async Task<IActionResult> RegisterUser([FromBody] RegisterUserModel<TUserDto> user) {
            var result = await _userAccountService.RegisterAsync(_mapper.Map<TUser>(user.UserInfo), user.Password);
            return MapResponse(result);
        }

        [HttpPost("login/external")]
        public virtual async Task<IActionResult> ExternalLogin([FromBody] ExternalAuthModel request) {
            var result = await _userAccountService.ExternalLoginAsync(request.Provider, request.Token);
            return MapResponse(result);
        }

        protected virtual IActionResult MapResponse(Result<TUser, Token> result) {
            return StatusCode((int)result.Code, new Result<TUserDto, Token>(result.Code, result.Errors) {
                Meta = result.Meta,
                Data = result.Data != default ? _mapper.Map<TUserDto>(result.Data) : default,
            });
        }
    }
}
