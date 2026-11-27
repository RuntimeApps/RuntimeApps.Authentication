using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;

namespace RuntimeApps.Authentication.Features.TwoFactor.Services;

/// <summary>
/// Fails startup when two-factor authentication is enabled but a service it depends on is not registered, so a
/// misconfigured application cannot start and silently skip or break the second step.
/// </summary>
internal sealed class TwoFactorDependenciesStartupValidator<TUser, TKey>(IServiceProviderIsService availability, IServiceScopeFactory scopeFactory) : IHostedService
    where TUser : class {
    public Task StartAsync(CancellationToken cancellationToken) {
        if(!availability.IsService(typeof(ITwoFactorChallengeStore<TKey>)))
            throw new InvalidOperationException(
                $"Two-factor authentication is enabled but no {nameof(ITwoFactorChallengeStore<TKey>)} is registered. " +
                "Register a store, for example services.AddTwoFactorChallengeStore<TDbContext, TKey>() from RuntimeApps.Authentication.EF.");
        if(!availability.IsService(typeof(IAuthenticationSessionIssuer<TUser>)))
            throw new InvalidOperationException(
                $"Two-factor authentication is enabled but no {nameof(IAuthenticationSessionIssuer<TUser>)} is registered. " +
                "Add a session issuer, for example AddJwtAuthenticationSessionIssuer() or AddCookieAuthenticationSessionIssuer().");

        using var scope = scopeFactory.CreateScope();
        if(!scope.ServiceProvider.GetServices<ITwoFactorMethod<TUser>>().Any())
            throw new InvalidOperationException("Two-factor authentication is enabled but no two-factor method is registered.");
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
