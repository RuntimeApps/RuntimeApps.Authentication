using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Controller {
    public abstract class BaseUserRoleController<TUser>: ControllerBase 
        where TUser: class {
        private readonly IUserManager<TUser> _userManager;

        protected BaseUserRoleController(IUserManager<TUser> userManager) => _userManager = userManager;

        [Route("{userId}/Role")]
        [HttpGet]
        public virtual async Task<IActionResult> GetUserRoles(string userId) {
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null) 
                return UserNotFound();

            var result = await _userManager.GetRolesAsync(user);
            return new ApiResult<IList<string>>(result);
        }

        [Route("{userId}/Role")]
        [HttpPost]
        public virtual async Task<IActionResult> AddUserRoles([FromRoute]string userId, [FromBody]IEnumerable<string> roles) {
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
                return UserNotFound();

            var result = await _userManager.AddToRolesAsync(user, roles);
            return new ApiResult(result);
        }

        [Route("{userId}/Role/{roleName}")]
        [HttpPost]
        public virtual async Task<IActionResult> AddUserRole([FromRoute] string userId, [FromRoute]string roleName) {
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
                return UserNotFound();

            var result = await _userManager.AddToRoleAsync(user, roleName);
            return new ApiResult(result);
        }

        [Route("{userId}/Role")]
        [HttpDelete]
        public virtual async Task<IActionResult> DeleteUserRoles([FromRoute] string userId, [FromBody] IEnumerable<string> roles) {
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
                return UserNotFound();

            var result = await _userManager.RemoveFromRolesAsync(user, roles);
            return new ApiResult(result);
        }

        [Route("{userId}/Role/{roleName}")]
        [HttpDelete]
        public virtual async Task<IActionResult> DeleteUserRole([FromRoute] string userId, [FromRoute] string roleName) {
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
                return UserNotFound();

            var result = await _userManager.RemoveFromRoleAsync(user, roleName);
            return new ApiResult(result);
        }

        protected virtual IActionResult UserNotFound() {
            return new ApiResult(ResultCode.BadRequest, "NotFound", "User not found");
        }
    }
}
