using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace RuntimeApps.Authentication.EF.Extensions {
    public static class RuntimeAppsAuthenticationBuilderExtension {
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddStores<TDbContext, TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder)
            where TDbContext : IdentityDbContext<TUser, TRole, TKey>
            where TUser : IdentityUser<TKey>, new()
            where TRole : IdentityRole<TKey>
            where TKey : IEquatable<TKey> {
            builder.Services.AddScoped<IUserStore<TUser>, EfUserStore<TUser, TRole, TKey>>();
            builder.Services.AddScoped<IdentityDbContext<TUser, TRole, TKey>>(p => p.GetService<TDbContext>());
            return builder;
        }
    }
}
