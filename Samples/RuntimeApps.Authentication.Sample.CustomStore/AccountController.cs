using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Controller;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Sample.CustomStore {
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController: BaseAccountController<IdentityUser, IdentityUserDto, string> {
        public AccountController(IUserAccountService<IdentityUser> userAccountService, IMapper mapper) : base(userAccountService, mapper) {
        }
    }
}
