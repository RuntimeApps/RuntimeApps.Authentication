using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Controller;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Sample {
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController: BaseAccountController<IdentityUser<int>, int> {
        public AccountController(IUserAccountService<IdentityUser<int>> userAccountService) : base(userAccountService) {
        }
    }
}
