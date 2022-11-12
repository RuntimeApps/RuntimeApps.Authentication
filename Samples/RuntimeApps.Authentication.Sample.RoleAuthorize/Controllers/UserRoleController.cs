using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Controller;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Sample.RoleAuthorize.Controllers {
    [Authorize(Roles = RoleConsts.UserManagerRole)]
    [Route("api/user")]
    [ApiController]
    public class UserRoleController: BaseUserRoleController<IdentityUser<int>> {
        public UserRoleController(IUserManager<IdentityUser<int>> userManager) : base(userManager) {
        }
    }
}
