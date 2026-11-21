using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Identity.Contracts;
namespace RuntimeApps.Authentication.Identity {
    public class RuntimeAppsUserManager<TUser>: UserManager<TUser>,
        IUserManager<TUser>, IUserPasswordManager<TUser>, IUserEmailManager<TUser>,
        IUserPhoneNumberManager<TUser>, IUserLoginManager<TUser>, IUserClaimManager<TUser>,
        IUserRoleManager<TUser>, IUserTwoFactorManager<TUser>, IUserLockoutManager<TUser>,
        IUserTokenManager<TUser>
        where TUser : class {
        public RuntimeAppsUserManager(IUserStore<TUser> store,
                                      IOptions<IdentityOptions> optionsAccessor,
                                      IPasswordHasher<TUser> passwordHasher,
                                      IEnumerable<IUserValidator<TUser>> userValidators,
                                      IEnumerable<IPasswordValidator<TUser>> passwordValidators,
                                      ILookupNormalizer keyNormalizer,
                                      IdentityErrorDescriber errors,
                                      IServiceProvider services,
                                      ILogger<UserManager<TUser>> logger) : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger) {
        }
    }
}
