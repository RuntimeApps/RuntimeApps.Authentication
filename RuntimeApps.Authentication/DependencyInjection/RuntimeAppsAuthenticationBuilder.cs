using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RuntimeApps.Authentication.Identity;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Identity.Models;

namespace RuntimeApps.Authentication.DependencyInjection {
    /// <summary>Builder for RuntimeApps core Identity integration and user mapping.</summary>
    public class RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey>
        where TUser : IdentityUser<TKey>, new()
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey> {
        public RuntimeAppsAuthenticationBuilder(AuthenticationBuilder authenticationBuilder) {
            ArgumentNullException.ThrowIfNull(authenticationBuilder);
            Authentication = authenticationBuilder;
            Services = authenticationBuilder.Services;
        }

        public AuthenticationBuilder Authentication { get; }
        public IServiceCollection Services { get; }

        /// <summary>Registers the Identity managers and RuntimeApps account service. Optional workflows are opt-in.</summary>
        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddAuthenticationServices() {
            Services.TryAddScoped<Features.Account.Contracts.IUserAccountService<TUser>, Features.Account.Services.UserAccountService<TUser, TKey>>();
            Services.AddHttpContextAccessor();
            Services.AddHttpClient();
            Services.TryAddScoped<IUserValidator<TUser>, UserValidator<TUser>>();
            Services.TryAddScoped<IPasswordValidator<TUser>, PasswordValidator<TUser>>();
            Services.TryAddScoped<IPasswordHasher<TUser>, PasswordHasher<TUser>>();
            Services.TryAddScoped<ILookupNormalizer, UpperInvariantLookupNormalizer>();
            Services.TryAddScoped<IRoleValidator<TRole>, RoleValidator<TRole>>();
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
            Services.TryAddScoped<IRoleManager<TRole>, RuntimeAppsRoleManager<TRole>>();
            AddBuiltInUserMappers();
            return this;
        }

        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddUserMapper<TUserDto, TMapper>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
            where TUserDto : class where TMapper : class, IUserMapper<TUser, TUserDto> {
            Services.Replace(ServiceDescriptor.Describe(typeof(IUserMapper<TUser, TUserDto>), typeof(TMapper), lifetime));
            return this;
        }
        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddUserMapper<TUserDto>(Func<TUser, TUserDto> toDto, Func<TUserDto, TUser> toUser) where TUserDto : class {
            ArgumentNullException.ThrowIfNull(toDto); ArgumentNullException.ThrowIfNull(toUser);
            Services.Replace(ServiceDescriptor.Singleton<IUserMapper<TUser, TUserDto>>(new DelegateUserMapper<TUser, TUserDto>(toDto, toUser)));
            return this;
        }
        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddDefaultUserMapper<TUserDto>() where TUserDto : IdentityUserDto<TKey>, new() => AddUserMapper<TUserDto, DefaultIdentityUserMapper<TUser, TUserDto, TKey>>();

        // Compatibility wrappers keep the original public builder surface while implementation lives in focused extensions.
        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddVerificationServices(Action<Features.Verification.Models.VerificationOptions> configureOptions = null) =>
            FeatureRegistrationExtensions.AddVerificationServices(this, configureOptions);
        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddForgotPassword(Action<Features.PasswordRecovery.Models.ForgotPasswordOptions> configureOptions = null) =>
            FeatureRegistrationExtensions.AddForgotPassword(this, configureOptions);
        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> UseJwt(string scheme, Action<Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions> configure) =>
            FeatureRegistrationExtensions.UseJwt(this, scheme, configure);
        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddValidators(Action<IdentityOptions> configure = null) =>
            FeatureRegistrationExtensions.AddValidators(this, configure);
        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddGoogleExternalLogin(Action<Features.ExternalLogin.Models.GoogleExternalLoginOption<TUser>> configure) =>
            FeatureRegistrationExtensions.AddGoogleExternalLogin(this, configure);
        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddFacebookExternalLogin(Action<Features.ExternalLogin.Models.FacebookExternalLoginOption<TUser>> configure) =>
            FeatureRegistrationExtensions.AddFacebookExternalLogin(this, configure);
        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddMicrosoftExternalLogin(Action<Features.ExternalLogin.Models.MicrosoftExternalLoginOption<TUser>> configure) =>
            FeatureRegistrationExtensions.AddMicrosoftExternalLogin(this, configure);

        public RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddStores<TUserStoreImpl, TRoleStoreImpl>()
            where TUserStoreImpl : UserStoreBase<TUser, TRole, TKey, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, IdentityUserLogin<TKey>, IdentityUserToken<TKey>, IdentityRoleClaim<TKey>>, IProtectedUserStore<TUser>
            where TRoleStoreImpl : class, IRoleClaimStore<TRole> {
            Services.TryAddScoped<TUserStoreImpl>();
            Services.TryAddScoped<TRoleStoreImpl>();
            AddUserStore<IUserStore<TUser>, TUserStoreImpl>(); AddUserStore<IUserLoginStore<TUser>, TUserStoreImpl>();
            AddUserStore<IUserClaimStore<TUser>, TUserStoreImpl>(); AddUserStore<IUserPasswordStore<TUser>, TUserStoreImpl>();
            AddUserStore<IUserSecurityStampStore<TUser>, TUserStoreImpl>(); AddUserStore<IUserEmailStore<TUser>, TUserStoreImpl>();
            AddUserStore<IUserLockoutStore<TUser>, TUserStoreImpl>(); AddUserStore<IUserPhoneNumberStore<TUser>, TUserStoreImpl>();
            AddUserStore<IQueryableUserStore<TUser>, TUserStoreImpl>(); AddUserStore<IUserTwoFactorStore<TUser>, TUserStoreImpl>();
            AddUserStore<IUserAuthenticationTokenStore<TUser>, TUserStoreImpl>(); AddUserStore<IUserAuthenticatorKeyStore<TUser>, TUserStoreImpl>();
            AddUserStore<IUserTwoFactorRecoveryCodeStore<TUser>, TUserStoreImpl>(); AddUserStore<IUserRoleStore<TUser>, TUserStoreImpl>();
            AddUserStore<IProtectedUserStore<TUser>, TUserStoreImpl>();
            Services.TryAddScoped<IRoleStore<TRole>>(sp => sp.GetRequiredService<TRoleStoreImpl>());
            Services.TryAddScoped<IRoleClaimStore<TRole>>(sp => sp.GetRequiredService<TRoleStoreImpl>());
            return this;
        }

        private void AddUserStore<TStore, TImplementation>() where TImplementation : class, TStore where TStore : class =>
            Services.TryAddScoped<TStore>(sp => sp.GetRequiredService<TImplementation>());

        private void AddBuiltInUserMappers() {
            Services.TryAddScoped<IUserMapper<TUser, IdentityUserDto<TKey>>, DefaultIdentityUserMapper<TUser, IdentityUserDto<TKey>, TKey>>();
            if (typeof(TKey) == typeof(string))
                Services.TryAdd(ServiceDescriptor.Scoped(typeof(IUserMapper<TUser, IdentityUserDto>), typeof(DefaultIdentityUserMapper<,,>).MakeGenericType(typeof(TUser), typeof(IdentityUserDto), typeof(TKey))));
        }
    }
}
