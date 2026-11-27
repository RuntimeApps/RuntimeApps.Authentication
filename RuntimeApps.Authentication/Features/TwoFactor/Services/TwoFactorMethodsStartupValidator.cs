using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;

namespace RuntimeApps.Authentication.Features.TwoFactor.Services;

/// <summary>Fails startup when registered two-factor methods have invalid or duplicate names.</summary>
internal sealed class TwoFactorMethodsStartupValidator<TUser>(IServiceScopeFactory scopeFactory) : IHostedService
    where TUser : class {
    // \z, not $: "$" would also accept a trailing newline.
    private static readonly Regex NamePattern = new(@"^[a-z][a-z0-9_-]{0,31}\z", RegexOptions.CultureInvariant);

    public Task StartAsync(CancellationToken cancellationToken) {
        using var scope = scopeFactory.CreateScope();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(var method in scope.ServiceProvider.GetServices<ITwoFactorMethod<TUser>>()) {
            var name = method.Name;
            if(name is null || !NamePattern.IsMatch(name))
                throw new InvalidOperationException($"Two-factor method '{method.GetType().Name}' has an invalid name. Names must match ^[a-z][a-z0-9_-]{{0,31}}$.");
            if(!names.Add(name))
                throw new InvalidOperationException($"More than one two-factor method is registered with the name '{name}'.");
        }
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
