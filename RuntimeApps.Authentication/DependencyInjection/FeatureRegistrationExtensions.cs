using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using RuntimeApps.Authentication.Features.Account.Services;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
using RuntimeApps.Authentication.Features.ExternalLogin.Providers;
using RuntimeApps.Authentication.Features.ExternalLogin.Services;
using RuntimeApps.Authentication.Features.PasswordRecovery.Contracts;
using RuntimeApps.Authentication.Features.PasswordRecovery.Models;
using RuntimeApps.Authentication.Features.PasswordRecovery.Services;
using RuntimeApps.Authentication.Features.Registration.Contracts;
using RuntimeApps.Authentication.Features.Registration.Services;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Features.Verification.Services;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.DependencyInjection {
    /// <summary>Opt-in feature registrations. Each method only adds the named feature's services.</summary>
    public static class FeatureRegistrationExtensions {
        /// <summary>Registers Identity's standard validators if the application has not supplied validators.</summary>
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddValidators<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, Action<IdentityOptions> configure = null)
            where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(builder);
            builder.Services.TryAddTransient<IPasswordValidator<TUser>, PasswordValidator<TUser>>();
            builder.Services.TryAddTransient<IUserValidator<TUser>, UserValidator<TUser>>();
            builder.Services.TryAddTransient<IRoleValidator<TRole>, RoleValidator<TRole>>();
            if (configure != null) builder.Services.Configure(configure);
            return builder;
        }
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddVerificationServices<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, IConfiguration configuration)
            where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> =>
            AddVerificationServices(builder, configuration, null);

        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddVerificationServices<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, Action<VerificationOptions> configureOptions = null)
            where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> =>
            AddVerificationServices(builder, null, configureOptions);

        private static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddVerificationServices<TUser, TRole, TKey>(RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, IConfiguration configuration, Action<VerificationOptions> configure)
            where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(builder);
            var options = builder.Services.AddOptions<VerificationOptions>();
            if (configuration != null) options.Bind(configuration.GetSection(VerificationOptions.SectionName));
            if (configure != null) options.Configure(configure);
            options.Validate(o => { try { o.Validate(); return true; } catch (InvalidOperationException) { return false; } }, "Verification options are invalid. Check code length, lifetime, attempt count, cooldown, and send limit.").ValidateOnStart();
            builder.Services.AddDataProtection();
            builder.Services.Configure<IdentityOptions>(o => o.SignIn.RequireConfirmedEmail = true);
            builder.Services.TryAddSingleton(TimeProvider.System);
            builder.Services.TryAddScoped<IVerificationCodeGenerator<TUser, TKey>, RandomVerificationCodeGenerator<TUser, TKey>>();
            builder.Services.TryAddScoped<IVerificationCodeVerifier<TKey>, DataProtectionVerificationCodeVerifier<TKey>>();
            builder.Services.TryAddScoped<IVerificationWorkflowService<TUser, TKey>, VerificationWorkflowService<TUser, TKey>>();
            builder.Services.TryAddScoped<IForgotPasswordVerificationWorkflow<TUser, TKey>, VerificationWorkflowService<TUser, TKey>>();
            builder.Services.TryAddScoped<IRegistrationService<TUser, TKey>, RegistrationService<TUser, TKey>>();
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, VerificationDependenciesStartupValidator<TUser, TKey>>());
            return builder;
        }

        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddForgotPassword<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, IConfiguration configuration)
            where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> => AddForgotPasswordCore(builder, configuration, null);
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddForgotPassword<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, IConfiguration configuration, Action<ForgotPasswordOptions> configureOptions)
            where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> => AddForgotPasswordCore(builder, configuration, configureOptions);
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddForgotPassword<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, Action<ForgotPasswordOptions> configureOptions = null)
            where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> => AddForgotPasswordCore(builder, null, configureOptions);
        private static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddForgotPasswordCore<TUser, TRole, TKey>(RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, IConfiguration configuration, Action<ForgotPasswordOptions> configure)
            where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(builder);
            var options = builder.Services.AddOptions<ForgotPasswordOptions>();
            if (configuration != null) options.Bind(configuration.GetSection(ForgotPasswordOptions.SectionName));
            if (configure != null) options.Configure(configure);
            options.Validate(o => { try { o.Validate(); return true; } catch (InvalidOperationException) { return false; } }, "Forgot-password options are invalid. Link mode requires an absolute HTTPS FrontendResetUrl.").ValidateOnStart();
            builder.Services.TryAddTransient<DataProtectorTokenProvider<TUser>>();
            builder.Services.Configure<IdentityOptions>(o => o.Tokens.ProviderMap.TryAdd(TokenOptions.DefaultProvider, new TokenProviderDescriptor(typeof(DataProtectorTokenProvider<TUser>))));
            builder.Services.TryAddScoped<IForgotPasswordService<TUser, TKey>, ForgotPasswordService<TUser, TKey>>();
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, VerificationDependenciesStartupValidator<TUser, TKey>>());
            return builder;
        }

        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> UseJwt<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, string scheme, Action<JwtBearerOptions> configure)
            where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(builder); ArgumentNullException.ThrowIfNull(configure);
            builder.Services.AddOptions<JwtBearerOptions>(scheme).ValidateOnStart();
            builder.Authentication.AddJwtBearer(scheme, configure);
            AddJwtProvider<TUser, TRole, TKey>(builder, scheme);
            builder.AddJwtAuthenticationSessionIssuer();
            return builder;
        }

        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> UseJwt<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, string scheme, IConfiguration configuration, Action<JwtBearerOptions> configure = null)
            where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(builder); ArgumentNullException.ThrowIfNull(configuration);
            const string section = "Authentication:Jwt";
            builder.Authentication.AddJwtBearer(scheme);
            var schemeOptions = builder.Services.AddOptions<JwtBearerOptions>(scheme).Bind(configuration.GetSection(section));
            if (configure != null) schemeOptions.Configure(configure);
            schemeOptions.ValidateOnStart();
            AddJwtProvider<TUser, TRole, TKey>(builder, scheme);
            builder.AddJwtAuthenticationSessionIssuer();
            return builder;
        }

        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddJwtAuthenticationSessionIssuer<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder)
            where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(builder);
            if(!RegisterSessionIssuer<TUser, RuntimeApps.Authentication.Features.Account.Services.JwtAuthenticationSessionIssuer<TUser, TKey>>(builder.Services)) return builder;
            builder.Services.AddScoped<RuntimeApps.Authentication.Features.Account.Contracts.IAuthenticationSessionIssuer<TUser>, RuntimeApps.Authentication.Features.Account.Services.JwtAuthenticationSessionIssuer<TUser, TKey>>();
            return builder;
        }

        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddCookieAuthenticationSessionIssuer<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, Action<RuntimeApps.Authentication.Features.Account.Models.CookieSessionOptions> configure = null)
            where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(builder);
            if(!RegisterSessionIssuer<TUser, RuntimeApps.Authentication.Features.Account.Services.CookieAuthenticationSessionIssuer<TUser, TKey>>(builder.Services)) return builder;
            builder.Services.AddOptions<RuntimeApps.Authentication.Features.Account.Models.CookieSessionOptions>();
            if(configure != null) builder.Services.Configure(configure);
            builder.Services.AddScoped<RuntimeApps.Authentication.Features.Account.Contracts.IAuthenticationSessionIssuer<TUser>, RuntimeApps.Authentication.Features.Account.Services.CookieAuthenticationSessionIssuer<TUser, TKey>>();
            return builder;
        }

        private static bool RegisterSessionIssuer<TUser, TIssuer>(IServiceCollection services) where TUser : class {
            var existing = services.LastOrDefault(d => d.ServiceType == typeof(RuntimeApps.Authentication.Features.Account.Contracts.IAuthenticationSessionIssuer<TUser>));
            if(existing == null) return true;
            if(existing.ImplementationType == typeof(TIssuer)) return false;
            throw new InvalidOperationException("A conflicting authentication session issuer is already registered for this user type.");
        }

        private static void AddJwtProvider<TUser, TRole, TKey>(RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, string scheme)
            where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> =>
            builder.Services.TryAddScoped<IJwtProvider<TUser>>(services => new JwtProvider<TUser, TKey>(
                services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<JwtBearerOptions>>().Get(scheme),
                services.GetRequiredService<Microsoft.AspNetCore.Identity.IUserClaimsPrincipalFactory<TUser>>()));

        private static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddProvider<TUser, TRole, TKey, TOption, TProvider>(RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> b, IConfiguration c, Action<TOption> configure)
            where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey>
            where TOption : BaseExternalLoginOption, new() where TProvider : class, IExternalLoginProvider<TUser> {
            ArgumentNullException.ThrowIfNull(b);
            var o = b.Services.AddOptions<TOption>();
            if (c != null) o.Bind(c.GetSection(TOptionSection<TOption>.Name));
            if (configure != null) o.Configure(configure);
            o.Validate(x => !string.IsNullOrWhiteSpace(x.ClientId) && !string.IsNullOrWhiteSpace(x.ClientSecret), "External login requires ClientId and ClientSecret.").ValidateOnStart();
            b.Services.TryAddEnumerable(ServiceDescriptor.Transient<IExternalLoginProvider<TUser>, TProvider>());
            b.Services.TryAddScoped<IExternalLoginEmailTrustPolicy<TUser>, DefaultExternalLoginEmailTrustPolicy<TUser>>();
            return b;
        }
        private static class TOptionSection<T> { public static string Name => typeof(T).Name.StartsWith("Google", StringComparison.Ordinal) ? "Authentication:ExternalLogin:Google" : typeof(T).Name.StartsWith("Facebook", StringComparison.Ordinal) ? "Authentication:ExternalLogin:Facebook" : "Authentication:ExternalLogin:Microsoft"; }
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddGoogleExternalLogin<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> b, Action<GoogleExternalLoginOption<TUser>> configure) where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> => AddProvider<TUser, TRole, TKey, GoogleExternalLoginOption<TUser>, GoogleExternalLoginProvider<TUser>>(b, null, configure);
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddGoogleExternalLogin<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> b, IConfiguration c, Action<GoogleExternalLoginOption<TUser>> configure = null) where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> => AddProvider<TUser, TRole, TKey, GoogleExternalLoginOption<TUser>, GoogleExternalLoginProvider<TUser>>(b, c, configure);
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddFacebookExternalLogin<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> b, Action<FacebookExternalLoginOption<TUser>> configure) where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> => AddProvider<TUser, TRole, TKey, FacebookExternalLoginOption<TUser>, FacebookExternalLoginProvider<TUser>>(b, null, configure);
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddFacebookExternalLogin<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> b, IConfiguration c, Action<FacebookExternalLoginOption<TUser>> configure = null) where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> => AddProvider<TUser, TRole, TKey, FacebookExternalLoginOption<TUser>, FacebookExternalLoginProvider<TUser>>(b, c, configure);
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddMicrosoftExternalLogin<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> b, Action<MicrosoftExternalLoginOption<TUser>> configure) where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> => AddProvider<TUser, TRole, TKey, MicrosoftExternalLoginOption<TUser>, MicrosoftExternalLoginProvider<TUser>>(b, null, configure);
        public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddMicrosoftExternalLogin<TUser, TRole, TKey>(this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> b, IConfiguration c, Action<MicrosoftExternalLoginOption<TUser>> configure = null) where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> => AddProvider<TUser, TRole, TKey, MicrosoftExternalLoginOption<TUser>, MicrosoftExternalLoginProvider<TUser>>(b, c, configure);
    }
}
