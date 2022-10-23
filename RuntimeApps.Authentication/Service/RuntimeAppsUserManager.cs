﻿using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Service {
    public class RuntimeAppsUserManager<TUser>: UserManager<TUser>, IUserManager<TUser>
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
