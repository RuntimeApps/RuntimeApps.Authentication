using RuntimeApps.Authentication.Controller;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Sample.CustomModel {
    public class AccountController: BaseAccountController<User, int> {
        public AccountController(IUserAccountService<User> userAccountService) : base(userAccountService) {
        }
    }
}
