using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.TwoFactor.Services;

namespace RuntimeApps.Authentication.DependencyInjection;

public static class TwoFactorBuilderExtensions {
    /// <summary>
    /// Enables API-based two-factor authentication with the built-in authenticator-app method.
    /// <see cref="TwoFactorOptions.Issuer"/> is required and validated at startup. Without this call
    /// no two-factor services are registered and existing authentication behavior is unchanged.
    /// </summary>
    public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddTwoFactor<TUser, TRole, TKey>(
        this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, Action<TwoFactorOptions> configure)
        where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> {
        ArgumentNullException.ThrowIfNull(configure);
        return AddTwoFactorCore(builder, null, configure);
    }

    /// <summary>Enables two-factor authentication, binding options from <c>Authentication:TwoFactor</c>.</summary>
    public static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddTwoFactor<TUser, TRole, TKey>(
        this RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, IConfiguration configuration, Action<TwoFactorOptions> configure = null)
        where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> {
        ArgumentNullException.ThrowIfNull(configuration);
        return AddTwoFactorCore(builder, configuration, configure);
    }

    /// <summary>Registers a custom method. Used by <c>RuntimeAppsAuthenticationBuilder.AddTwoFactorMethod</c>.</summary>
    internal static void AddTwoFactorMethodCore<TUser, TMethod>(IServiceCollection services)
        where TUser : class where TMethod : class, ITwoFactorMethod<TUser> {
        services.TryAddEnumerable(ServiceDescriptor.Scoped<ITwoFactorMethod<TUser>, TMethod>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, TwoFactorMethodsStartupValidator<TUser>>());
    }

    private static RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> AddTwoFactorCore<TUser, TRole, TKey>(
        RuntimeAppsAuthenticationBuilder<TUser, TRole, TKey> builder, IConfiguration configuration, Action<TwoFactorOptions> configure)
        where TUser : IdentityUser<TKey>, new() where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> {
        ArgumentNullException.ThrowIfNull(builder);
        var options = builder.Services.AddOptions<TwoFactorOptions>();
        if(configuration != null) options.Bind(configuration.GetSection(TwoFactorOptions.SectionName));
        if(configure != null) options.Configure(configure);
        options.Validate(o => { try { o.Validate(); return true; } catch(InvalidOperationException) { return false; } },
            "Two-factor options are invalid. An Issuer is required; check the challenge, retention, cleanup and attempt settings.").ValidateOnStart();

        // Identity resolves provider types from DI when UserManager is created.
        builder.Services.TryAddTransient<AuthenticatorTokenProvider<TUser>>();
        builder.Services.Configure<IdentityOptions>(o => o.Tokens.ProviderMap.TryAdd(
            TokenOptions.DefaultAuthenticatorProvider, new TokenProviderDescriptor(typeof(AuthenticatorTokenProvider<TUser>))));
        builder.Services.TryAddEnumerable(ServiceDescriptor.Scoped<ITwoFactorMethod<TUser>, AuthenticatorTwoFactorMethod<TUser>>());
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, TwoFactorMethodsStartupValidator<TUser>>());
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, TwoFactorDependenciesStartupValidator<TUser, TKey>>());
        builder.Services.TryAddSingleton<TwoFactorFeatureMarker>();
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.TryAddSingleton<ITwoFactorRequestLimiter, TwoFactorRequestLimiter>();
        builder.Services.TryAddScoped<TwoFactorAccountEligibility<TUser, TKey>>();
        builder.Services.TryAddScoped<ITwoFactorLoginService<TUser>, TwoFactorLoginService<TUser, TKey>>();
        builder.Services.TryAddScoped<ITwoFactorCleanupService<TKey>, TwoFactorCleanupService<TKey>>();
        return builder;
    }
}
