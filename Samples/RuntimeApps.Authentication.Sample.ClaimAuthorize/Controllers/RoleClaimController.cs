using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Controller;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Sample.ClaimAuthorize.Controllers {
    [Authorize(PolicyConsts.ManageRoleClaimPolicy)]
    [Route("api/role")]
    [ApiController]
    public class RoleClaimController: BaseRoleClaimController<IdentityRole<int>> {
        public RoleClaimController(IRoleManager<IdentityRole<int>> roleManager) : base(roleManager) {
        }
    }
}
