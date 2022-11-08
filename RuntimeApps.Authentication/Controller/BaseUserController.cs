using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Controller {
    public abstract class BaseUserController<TUser, TUserDto>: ControllerBase
        where TUser : class
        where TUserDto : class {
        private readonly IUserManager<TUser> _userManager;
        private readonly IMapper _mapper;

        protected BaseUserController(IUserManager<TUser> userManager, IMapper mapper) {
            _userManager = userManager;
            _mapper = mapper;
        }

        [Route("{userId}")]
        [HttpGet]
        public virtual async Task<IActionResult> GetByIdAsync(string userId) {
            var user = await _userManager.FindByIdAsync(userId);
            return new ApiResult<TUserDto>(user != default ? _mapper.Map<TUserDto>(user) : default);
        }

        [HttpGet]
        public virtual async Task<IActionResult> GetByUserNameAsync([FromQuery] string userName) {
            var user = await _userManager.FindByNameAsync(userName);
            return new ApiResult<TUserDto>(user != default ? _mapper.Map<TUserDto>(user) : default);
        }

    }
}
