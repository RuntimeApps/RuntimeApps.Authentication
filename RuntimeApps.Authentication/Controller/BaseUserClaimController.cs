using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Controller {
    public abstract class BaseUserClaimController<TUser>: ControllerBase
        where TUser : class {
        private readonly IUserManager<TUser> _userManager;

        protected BaseUserClaimController(IUserManager<TUser> userManager) => _userManager = userManager;

        [Route("{userId}/claim")]
        [HttpGet]
        public virtual async Task<IActionResult> GetAsync(string userId) {
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
                return UserNotFound();

            var result = await _userManager.GetClaimsAsync(user);
            return new ApiResult<IList<Claim>>(result);
        }

        [Route("{userId}/claim")]
        [HttpPost]
        public virtual async Task<IActionResult> AddAsync([FromRoute] string userId, [FromBody] Claim claim) {
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
                return UserNotFound();

            var result = await _userManager.AddClaimAsync(user, claim);
            return new ApiResult(result);
        }

        [Route("{userId}/claim")]
        [HttpDelete]
        public virtual async Task<IActionResult> DeleteAsync([FromRoute] string userId, [FromBody] Claim claim) {
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
                return UserNotFound();

            var result = await _userManager.RemoveClaimAsync(user, claim);
            return new ApiResult(result);
        }

        [Route("{userId}/claim/bulk")]
        [HttpPost]
        public virtual async Task<IActionResult> AddBulkAsync([FromRoute] string userId, [FromBody] IEnumerable<Claim> claims) {
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
                return UserNotFound();

            var result = await _userManager.AddClaimsAsync(user, claims);
            return new ApiResult(result);
        }

        [Route("{userId}/claim/bulk")]
        [HttpDelete]
        public virtual async Task<IActionResult> DeleteAsync([FromRoute] string userId, [FromBody] IEnumerable<Claim> claims) {
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
                return UserNotFound();

            var result = await _userManager.RemoveClaimsAsync(user, claims);
            return new ApiResult(result);
        }

        protected virtual IActionResult UserNotFound() {
            return new ApiResult(ResultCode.BadRequest, "NotFound", "User not found");
        }
    }
}
