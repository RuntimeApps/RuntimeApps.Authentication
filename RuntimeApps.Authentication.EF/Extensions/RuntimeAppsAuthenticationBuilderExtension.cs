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
            builder.Services.AddScoped<IUserStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IUserLoginStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IUserClaimStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IUserPasswordStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IUserSecurityStampStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IUserEmailStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IUserLockoutStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IUserPhoneNumberStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IQueryableUserStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IQueryableUserStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IUserTwoFactorStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IUserAuthenticationTokenStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IUserAuthenticatorKeyStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IUserTwoFactorRecoveryCodeStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IProtectedUserStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            builder.Services.AddScoped<IUserRoleStore<TUser>, UserStore<TUser, TRole, TDbContext, TKey>>();
            return builder;
        }
    }
}
