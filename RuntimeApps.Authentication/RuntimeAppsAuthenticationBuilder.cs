using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
            Authentication = authenticationBuilder ?? throw new NullReferenceException(nameof(authenticationBuilder));
            Services = authenticationBuilder.Services;
        }

        public AuthenticationBuilder Authentication { get; set; }
        public IServiceCollection Services { get; set; }

        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddAuthenticationServices() {
            Services.TryAddScoped<IUserAccountService<TUser>, UserAccountService<TUser, TKey>>();

            Services.AddHttpContextAccessor();
            // Identity services
            Services.TryAddScoped<IUserValidator<TUser>, UserValidator<TUser>>();
            Services.TryAddScoped<IPasswordValidator<TUser>, PasswordValidator<TUser>>();
            Services.TryAddScoped<IPasswordHasher<TUser>, PasswordHasher<TUser>>();
            Services.TryAddScoped<ILookupNormalizer, UpperInvariantLookupNormalizer>();
            Services.TryAddScoped<IRoleValidator<TRole>, RoleValidator<TRole>>();
            // No interface for the error describer so we can add errors without rev'ing the interface
            Services.TryAddScoped<IdentityErrorDescriber>();
            Services.TryAddScoped<ISecurityStampValidator, SecurityStampValidator<TUser>>();
            Services.TryAddScoped<ITwoFactorSecurityStampValidator, TwoFactorSecurityStampValidator<TUser>>();
            Services.TryAddScoped<IUserClaimsPrincipalFactory<TUser>, UserClaimsPrincipalFactory<TUser, TRole>>();
            Services.TryAddScoped<IUserConfirmation<TUser>, DefaultUserConfirmation<TUser>>();
            Services.TryAddScoped<UserManager<TUser>>();
            Services.TryAddScoped<IUserManager<TUser>, RuntimeAppsUserManager<TUser>>();
            Services.TryAddScoped<SignInManager<TUser>>();
            Services.TryAddScoped<ISignInManager<TUser>, RuntimeAppsSignInManager<TUser>>();
            Services.TryAddScoped<RoleManager<TRole>>();
            return this;
        }

        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> UseJwt(string authenticationScheme, Action<JwtBearerOptions> configureOptions) {
            Services.TryAddScoped<IJwtProvider<TUser>, JwtProvider<TUser, TKey>>();
            Services.Configure(configureOptions);
            Authentication.AddJwtBearer(authenticationScheme, configureOptions);
            return this;
        }

        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddGoogleExternalLogin(Action<GoogleExternalLoginOption<TUser>> option) {
            Services.TryAddTransient<IExternalLoginProvider<TUser>, GoogleExternalLoginProvider<TUser>>();
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

        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddValidators(Action<IdentityOptions> identityOption = null) {
            Services.TryAddTransient<IPasswordValidator<TUser>, PasswordValidator<TUser>>();
            Services.TryAddTransient<IUserValidator<TUser>, UserValidator<TUser>>();
            if(identityOption != null)
                Services.Configure(identityOption);
            return this;
        }

        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddStores<TUserStoreImpl, TRoleStoreImpl>() 
            where TUserStoreImpl: UserStoreBase<TUser, TRole, TKey, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, IdentityUserLogin<TKey>, IdentityUserToken<TKey>, IdentityRoleClaim<TKey>>, IProtectedUserStore<TUser>
            where TRoleStoreImpl: class, IRoleClaimStore<TRole> {
            Services.TryAddScoped<IUserStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IUserLoginStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IUserClaimStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IUserPasswordStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IUserSecurityStampStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IUserEmailStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IUserLockoutStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IUserPhoneNumberStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IQueryableUserStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IQueryableUserStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IUserTwoFactorStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IUserAuthenticationTokenStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IUserAuthenticatorKeyStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IUserTwoFactorRecoveryCodeStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IUserRoleStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IProtectedUserStore<TUser>, TUserStoreImpl>();

            Services.TryAddScoped<IRoleStore<TRole>, TRoleStoreImpl>();
            Services.TryAddScoped<IRoleClaimStore<TRole>, TRoleStoreImpl>();
            return this;
        }
    }
}
