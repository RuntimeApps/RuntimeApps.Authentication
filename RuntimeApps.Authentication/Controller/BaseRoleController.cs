using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Controller {
    public abstract class BaseRoleController<TRole>: ControllerBase
        where TRole : class {
        private readonly IRoleManager<TRole> _roleManager;

        public BaseRoleController(IRoleManager<TRole> roleManager) => _roleManager = roleManager;

        [HttpPost]
        public virtual async Task<IActionResult> CreateAsync(TRole role) {
            var result = await _roleManager.CreateAsync(role);
            return new ApiResult<TRole>(result, role);
        }

        [HttpPut]
        public virtual async Task<IActionResult> UpdateAsync(TRole role) {
            var updateResult = await _roleManager.UpdateAsync(role);
            return new ApiResult(updateResult);
        }

        [Route("{roleId}")]
        [HttpDelete]
        public virtual async Task<IActionResult> DeleteAsync(string roleId) {
            var role = await _roleManager.FindByIdAsync(roleId);
            if(role == null)
                return new ApiResult(ResultCode.BadRequest, "NotFound", "Role Not Found");

            var result = await _roleManager.DeleteAsync(role);
            return new ApiResult(result);
        }

        [Route("{roleId}")]
        [HttpGet]
        public virtual async Task<IActionResult> GetAsync(string roleId) {
            var role = await _roleManager.FindByIdAsync(roleId);
            return new ApiResult<TRole>(role);
        }

        [HttpGet]
        public virtual async Task<IActionResult> GetByNameAsync([FromQuery] string name) {
            var role = await _roleManager.FindByNameAsync(name);
            return new ApiResult<TRole>(role);
        }

        [HttpGet]
        public virtual Task<IActionResult> GetAllRoles() {
            var roles = _roleManager.Roles.ToList();
            return Task.FromResult<IActionResult>(new ApiResult<IEnumerable<TRole>>(roles));
        }
    }
}
