using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace RuntimeApps.Authentication.EF.Extensions {
    public static class RuntimeAppsAuthenticationBuilderExtension {
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddEfStores<TDbContext, TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder)
            where TDbContext : IdentityDbContext<TUser, TRole, TKey>
            where TUser : IdentityUser<TKey>, new()
            where TRole : IdentityRole<TKey>
            where TKey : IEquatable<TKey> {
            builder.AddStores<UserStore<TUser, TRole, TDbContext, TKey>, 
                RoleStore<TRole, TDbContext, TKey>>();
            return builder;
        }
    }
}
