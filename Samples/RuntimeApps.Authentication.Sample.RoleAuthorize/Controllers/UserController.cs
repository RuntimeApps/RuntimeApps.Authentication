using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Controller;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Sample.RoleAuthorize.Controllers {
    [Authorize(Roles = $"{RoleConsts.UserViewRole},{RoleConsts.UserManagerRole}")]
    [Route("api/user")]
    [ApiController]
    public class UserController: BaseUserController<IdentityUser<int>, IdentityUserDto<int>> {
        public UserController(IUserManager<IdentityUser<int>> userManager, IMapper mapper) : base(userManager, mapper) {
        }
    }
}
