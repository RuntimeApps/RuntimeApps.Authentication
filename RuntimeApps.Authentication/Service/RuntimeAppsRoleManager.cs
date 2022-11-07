using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Service {
    public class RuntimeAppsRoleManager<TRole>: RoleManager<TRole>, IRoleManager<TRole>
        where TRole : class {
        public RuntimeAppsRoleManager(IRoleStore<TRole> store, IEnumerable<IRoleValidator<TRole>> roleValidators, ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, ILogger<RoleManager<TRole>> logger) : base(store, roleValidators, keyNormalizer, errors, logger) {
        }
    }
}
