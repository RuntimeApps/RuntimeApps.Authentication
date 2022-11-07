﻿using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Controller {
    public abstract class BaseRoleClaimController<TRole>: ControllerBase
        where TRole : class {
        private readonly IRoleManager<TRole> _roleManager;

        protected BaseRoleClaimController(IRoleManager<TRole> roleManager) => _roleManager = roleManager;

        [Route("{roleId}/Claim")]
        [HttpGet]
        public virtual async Task<IActionResult> GetAsync(string roleId) {
            var role = await _roleManager.FindByIdAsync(roleId);
            if(role == null)
                return new ApiResult(ResultCode.BadRequest, "NotFound", "Role Not Found");

            var result = await _roleManager.GetClaimsAsync(role);
            return new ApiResult<IEnumerable<Claim>>(result);
        }

        [Route("{roleId}/Claim")]
        [HttpPost]
        public virtual async Task<IActionResult> AddAsync([FromRoute] string roleId, [FromBody] Claim claim) {
            var role = await _roleManager.FindByIdAsync(roleId);
            if(role == null)
                return new ApiResult(ResultCode.BadRequest, "NotFound", "Role Not Found");

            var result = await _roleManager.AddClaimAsync(role, claim);
            return new ApiResult(result);
        }

        [Route("{roleId}/Claim")]
        [HttpDelete]
        public virtual async Task<IActionResult> DeleteAsync([FromRoute] string roleId, [FromBody] Claim claim) {
            var role = await _roleManager.FindByIdAsync(roleId);
            if(role == null)
                return new ApiResult(ResultCode.BadRequest, "NotFound", "Role Not Found");

            var result = await _roleManager.RemoveClaimAsync(role, claim);
            return new ApiResult(result);
        }

    }
}
