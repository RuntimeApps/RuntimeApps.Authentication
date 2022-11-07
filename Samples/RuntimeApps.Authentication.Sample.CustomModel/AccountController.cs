using AutoMapper;
using RuntimeApps.Authentication.Controller;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Sample.CustomModel {
    public class AccountController: BaseAccountController<User, UserDto, int> {
        public AccountController(IUserAccountService<User> userAccountService, IMapper mapper, IUserManager<User> userManager) : base(userAccountService, mapper, userManager) {
        }
    }
}
