using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Sample.CustomValidation.UserValidators {
    public class UserNameMustBeEmailValidator: IUserValidator<IdentityUser> {
        public Task<IdentityResult> ValidateAsync(UserManager<IdentityUser> manager, IdentityUser user) {
            if(!user.UserName.Equals(user.Email, StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(IdentityResult.Failed(new IdentityError() {
                    Code = "InvalidUsername",
                    Description = "Username must be your email"
                }));

            return Task.FromResult(IdentityResult.Success);
        }
    }
}
