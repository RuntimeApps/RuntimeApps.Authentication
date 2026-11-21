using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.DependencyInjection {
    public static class AuthenticationBuilderExtensions {
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddRuntimeAppsAuthentication<TUser, TRole, TKey>(this AuthenticationBuilder builder)
            where TUser : IdentityUser<TKey>, new()
            where TRole : IdentityRole<TKey>
            where TKey : IEquatable<TKey> {
            var authenticationBuilder = new RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey>(builder);
            authenticationBuilder.AddAuthenticationServices();
            return authenticationBuilder;
        }
    }
}
