using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Controller;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Sample.RoleAuthorize.Controllers {
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController: BaseAccountController<IdentityUser<int>, IdentityUserDto<int>, int> {
        public AccountController(IUserAccountService<IdentityUser<int>> userAccountService, IMapper mapper, IUserManager<IdentityUser<int>> userManager) : base(userAccountService, mapper, userManager) {
        }

        [Authorize(Roles = RoleConsts.UserManagerRole)]
        public override Task<IActionResult> RegisterUser([FromBody] RegisterUserModel<IdentityUserDto<int>> user) => base.RegisterUser(user);
    }
}
