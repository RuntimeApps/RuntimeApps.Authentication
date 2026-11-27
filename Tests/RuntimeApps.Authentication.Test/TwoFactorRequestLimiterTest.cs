using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.TwoFactor.Services;

namespace RuntimeApps.Authentication.Test;

public class TwoFactorRequestLimiterTest {
    private static TwoFactorRequestLimiter Create(int perMinute) =>
        new(Options.Create(new TwoFactorOptions { Issuer = "Acme", CompleteRequestsPerMinute = perMinute }));

    private static HttpContext From(string ip) {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = ip == null ? null : IPAddress.Parse(ip);
        return context;
    }

    [Fact]
    public async Task RejectsRequestsOverTheLimit() {
        using var limiter = Create(3);
        var token = TestContext.Current.CancellationToken;

        for(var i = 0; i < 3; i++)
            Assert.True(await limiter.IsAllowedAsync(From("10.0.0.1"), token));

        Assert.False(await limiter.IsAllowedAsync(From("10.0.0.1"), token));
        Assert.False(await limiter.IsAllowedAsync(From("10.0.0.1"), token));
    }

    [Fact]
    public async Task CountsEachClientAddressSeparately() {
        using var limiter = Create(1);
        var token = TestContext.Current.CancellationToken;

        Assert.True(await limiter.IsAllowedAsync(From("10.0.0.1"), token));
        Assert.False(await limiter.IsAllowedAsync(From("10.0.0.1"), token));
        Assert.True(await limiter.IsAllowedAsync(From("10.0.0.2"), token));
    }

    [Fact]
    public async Task RequestsWithoutAddressShareOnePartition() {
        using var limiter = Create(1);
        var token = TestContext.Current.CancellationToken;

        Assert.True(await limiter.IsAllowedAsync(From(null), token));
        Assert.False(await limiter.IsAllowedAsync(From(null), token));
    }

    [Fact]
    public async Task NullContext_IsRejectedWithArgumentException() {
        using var limiter = Create(1);

        await Assert.ThrowsAsync<ArgumentNullException>(async () => await limiter.IsAllowedAsync(null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AddTwoFactor_RegistersLimiterThatHonorsConfiguredLimit() {
        var services = Services();
        Builder(services).AddTwoFactor(o => { o.Issuer = "Acme"; o.CompleteRequestsPerMinute = 2; });
        await using var provider = services.BuildServiceProvider();
        var limiter = provider.GetRequiredService<ITwoFactorRequestLimiter>();
        var token = TestContext.Current.CancellationToken;

        Assert.Same(limiter, provider.GetRequiredService<ITwoFactorRequestLimiter>());
        Assert.True(await limiter.IsAllowedAsync(From("10.0.0.1"), token));
        Assert.True(await limiter.IsAllowedAsync(From("10.0.0.1"), token));
        Assert.False(await limiter.IsAllowedAsync(From("10.0.0.1"), token));
    }

    [Fact]
    public void AddTwoFactor_KeepsCustomLimiterRegisteredBeforeIt() {
        var services = Services();
        var custom = Mock.Of<ITwoFactorRequestLimiter>();
        services.AddSingleton(custom);
        Builder(services).AddTwoFactor(o => o.Issuer = "Acme");
        using var provider = services.BuildServiceProvider();

        Assert.Same(custom, provider.GetRequiredService<ITwoFactorRequestLimiter>());
    }

    private static ServiceCollection Services() {
        var services = new ServiceCollection();
        services.AddSingleton<IUserStore<IdentityUser>>(Mock.Of<IUserStore<IdentityUser>>());
        services.AddSingleton<IRoleStore<IdentityRole>>(Mock.Of<IRoleStore<IdentityRole>>());
        return services;
    }

    private static RuntimeAppsAuthenticationBuilder<IdentityUser, IdentityRole, string> Builder(IServiceCollection services) =>
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();
}
