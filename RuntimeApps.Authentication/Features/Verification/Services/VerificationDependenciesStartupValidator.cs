using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using RuntimeApps.Authentication.Features.PasswordRecovery.Contracts;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.Features.Verification.Services;

internal sealed class VerificationDependenciesStartupValidator<TUser, TKey>(IServiceScopeFactory scopeFactory) : IHostedService
    where TUser : class where TKey : IEquatable<TKey> {
    public Task StartAsync(CancellationToken cancellationToken) {
        using var scope = scopeFactory.CreateScope();
        var services = scope.ServiceProvider;
        Require<IVerificationRequestStore<TKey>>(services, "Register a persistent verification request store (for example, AddVerificationRequestStore<TDbContext, TKey>).");
        Require<IVerificationSender<TUser, TKey>>(services, "Register an IVerificationSender<TUser, TKey> delivery service.");
        Require<IVerificationWorkflowService<TUser, TKey>>(services, "Register the verification feature with AddVerificationServices.");
        return Task.CompletedTask;
    }
    private static void Require<TService>(IServiceProvider services, string guidance) where TService : notnull {
        try { _ = services.GetRequiredService<TService>(); }
        catch (InvalidOperationException exception) {
            throw new InvalidOperationException($"The verification feature is enabled but required service '{typeof(TService).Name}' is missing. {guidance}", exception);
        }
    }
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
