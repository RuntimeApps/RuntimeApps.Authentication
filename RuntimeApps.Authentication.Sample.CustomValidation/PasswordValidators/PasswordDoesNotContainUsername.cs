using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Sample.CustomValidation.PasswordValidators {
    public class PasswordDoesNotContainUsername: IPasswordValidator<IdentityUser> {
        public Task<IdentityResult> ValidateAsync(UserManager<IdentityUser> manager, IdentityUser user, string password) {
            if(password.Contains(user.UserName, StringComparison.OrdinalIgnoreCase)) {
                return Task.FromResult(IdentityResult.Failed(new IdentityError() {
                    Code = "InvalidPassword",
                    Description = "Password must not contains username"
                }));
            }
            return Task.FromResult(IdentityResult.Success);
        }
    }
}
