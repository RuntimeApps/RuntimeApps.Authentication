using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace RuntimeApps.Authentication.Sample.ClaimAuthorize.Controllers {
    [Authorize(PolicyConsts.ViewUserPolicy)]
    [Route("api/[controller]")]
    [ApiController]
    public class ClaimController: ControllerBase {
        [HttpGet]
        public IActionResult Get() => Ok(ClaimConsts.GetAllClaimData());
    }
}
