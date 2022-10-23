using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;
using RuntimeApps.Authentication.Service;
using RuntimeApps.Authentication.Service.ExternalLoginProviders;

namespace RuntimeApps.Authentication {
    public class RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey>
        where TUser : IdentityUser<TKey>, new()
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey> {

        public RuntimeAppsAuthenticationBuilder(AuthenticationBuilder authenticationBuilder) {
            if(authenticationBuilder == null)
                throw new NullReferenceException(nameof(authenticationBuilder));

            Authentication = authenticationBuilder;
            Services = authenticationBuilder.Services;
        }

        public AuthenticationBuilder Authentication { get; set; }
        public IServiceCollection Services { get; set; }

        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddAuthenticationServices() {
            Services.AddScoped<IUserAccountService<TUser>, UserAccountService<TUser, TKey>>();
            Services.AddScoped<UserManager<TUser>>();
            Services.AddScoped<IUserManager<TUser>, RuntimeAppsUserManager<TUser>>();
            Services.AddScoped<IPasswordHasher<TUser>, PasswordHasher<TUser>>();
            Services.AddScoped<ILookupNormalizer, UpperInvariantLookupNormalizer>();
            Services.AddScoped<IdentityErrorDescriber>();
            return this;
        }

        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> UseJwt(Action<JwtBearerOptions> configureOptions) {
            Services.AddScoped<IJwtProvider<TUser>, JwtProvider<TUser, TKey>>();
            Authentication.AddJwtBearer(configureOptions);
            return this;
        }

        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddGoogleExternalLogin(Action<GoogleExternalLoginOption<TUser>> option) {
            Services.AddTransient<IExternalLoginProvider<TUser>, GoogleExternalLoginProvider<TUser>>();
            Services.Configure(option);
            return this;
        }

        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddFacebookExternalLogin(Action<FacebookExternalLoginOption<TUser>> option) {
            Services.AddTransient<IExternalLoginProvider<TUser>, FacebookExternalLoginProvider<TUser>>();
            Services.Configure(option);
            return this;
        }

        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddMicrosoftExternalLogin(Action<MicrosoftExternalLoginOption<TUser>> option) {
            Services.AddTransient<IExternalLoginProvider<TUser>, MicrosoftExternalLoginProvider<TUser>>();
            Services.Configure(option);
            return this;
        }

    }
}
