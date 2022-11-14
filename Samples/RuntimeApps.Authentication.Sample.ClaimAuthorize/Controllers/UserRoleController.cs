using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Controller;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Sample.ClaimAuthorize.Controllers {
    [Authorize(PolicyConsts.ManageUserRolePolicy)]
    [Route("api/user")]
    [ApiController]
    public class UserRoleController: BaseUserRoleController<IdentityUser<int>> {
        public UserRoleController(IUserManager<IdentityUser<int>> userManager) : base(userManager) {
        }
    }
}
