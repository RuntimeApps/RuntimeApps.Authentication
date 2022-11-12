using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Controller;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Sample.RoleAuthorize.Controllers {
    [Authorize(Roles = RoleConsts.UserManagerRole)]
    [Authorize(Roles = RoleConsts.UserViewRole)]
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController: BaseRoleController<IdentityRole<int>> {
        public RoleController(IRoleManager<IdentityRole<int>> roleManager) : base(roleManager) {
        }

        public override Task<IActionResult> CreateAsync(IdentityRole<int> role) => NotImplemetedResponse();

        public override Task<IActionResult> UpdateAsync(IdentityRole<int> role) => NotImplemetedResponse();

        public override Task<IActionResult> DeleteAsync(string roleId) => NotImplemetedResponse();

        private Task<IActionResult> NotImplemetedResponse() =>
            Task.FromResult<IActionResult>(NotFound());
    }
}
