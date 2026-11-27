using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RuntimeApps.Authentication.EF.Features.TwoFactor.Stores;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;

namespace RuntimeApps.Authentication.EF.DependencyInjection;

public static class TwoFactorChallengeStoreBuilderExtensions {
    /// <summary>Registers the EF Core two-factor challenge store (it also supports cleanup).</summary>
    public static IServiceCollection AddTwoFactorChallengeStore<TDbContext, TKey>(this IServiceCollection services)
        where TDbContext : DbContext
        where TKey : IEquatable<TKey> {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<ITwoFactorChallengeStore<TKey>, EfTwoFactorChallengeStore<TDbContext, TKey>>();
        return services;
    }
}
