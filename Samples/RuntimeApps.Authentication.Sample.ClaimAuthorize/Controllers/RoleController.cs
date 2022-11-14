using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Controller;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Sample.ClaimAuthorize.Controllers {
    [Authorize(PolicyConsts.ManageRolePolicy)]
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController: BaseRoleController<IdentityRole<int>> {
        public RoleController(IRoleManager<IdentityRole<int>> roleManager) : base(roleManager) {
        }
    }
}
