using RuntimeApps.Authentication.DependencyInjection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using RuntimeApps.Authentication.EF.Identity;

namespace RuntimeApps.Authentication.EF.DependencyInjection {
    public static class RuntimeAppsAuthenticationBuilderExtension {
        /// <summary>
        /// Registers the ASP.NET Core Identity EF stores. The DbContext does not have to derive from
        /// <see cref="IdentityDbContext{TUser, TRole, TKey}"/>, but its model must contain the default
        /// Identity entities for <typeparamref name="TUser"/>, <typeparamref name="TRole"/> and
        /// <typeparamref name="TKey"/>. This is verified at application start.
        /// </summary>
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddEfStores<TDbContext, TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder)
            where TDbContext : DbContext
            where TUser : IdentityUser<TKey>, new()
            where TRole : IdentityRole<TKey>
            where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(builder);
            builder.AddStores<UserStore<TUser, TRole, TDbContext, TKey>,
                RoleStore<TRole, TDbContext, TKey>>();
            builder.Services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IHostedService, EfIdentityModelStartupValidator<TDbContext, TUser, TRole, TKey>>());
            return builder;
        }
    }
}
