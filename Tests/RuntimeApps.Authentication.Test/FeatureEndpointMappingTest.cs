using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using RuntimeApps.Authentication.Endpoints.Account;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Features.Registration.Contracts;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.Test;

public sealed class FeatureEndpointMappingTest {
    [Fact]
    public void AuthenticationMapping_DoesNotMapSessionEndpoints() {
        using var host = CreateHost(includeVerificationDependencies: false);

        host.Endpoints.MapGroup("api/auth")
            .MapAuthenticationApi<IdentityUser<int>, TestUserDto, int>();

        var endpoint = Assert.Single(Endpoints(host));
        Assert.Equal("api/auth/login", ((RouteEndpoint)endpoint).RoutePattern.RawText);
        Assert.IsAssignableFrom<IAllowAnonymous>(endpoint.Metadata.GetMetadata<IAllowAnonymous>());
    }

    [Fact]
    public void AuthenticationMetadata_DeclaresTokenFreeTwoFactorContinuation() {
        using var host = CreateHost(includeVerificationDependencies: false);
        host.Endpoints.MapAuthenticationApi<IdentityUser<int>, TestUserDto, int>();

        var login = Assert.Single(Endpoints(host).OfType<RouteEndpoint>());
        var accepted = Assert.Single(login.Metadata.GetOrderedMetadata<Microsoft.AspNetCore.Http.Metadata.IProducesResponseTypeMetadata>()
            .Where(metadata => metadata.StatusCode == StatusCodes.Status202Accepted));
        Assert.Equal(typeof(AuthenticationContinuationResponse), accepted.Type);
        Assert.DoesNotContain(typeof(RuntimeApps.Authentication.Shared.Models.Token).Name, accepted.Type!.GetProperties().Select(property => property.Name));
    }

    [Fact]
    public void RegistrationMapping_IsIndependentAndAnonymous() {
        using var host = CreateHost(includeVerificationDependencies: true);

        host.Endpoints.MapGroup("api/register")
            .MapRegistrationApi<IdentityUser<int>, TestUserDto, int>();

        var endpoint = Assert.Single(Endpoints(host));
        Assert.Equal("api/register/register", ((RouteEndpoint)endpoint).RoutePattern.RawText);
        Assert.IsAssignableFrom<IAllowAnonymous>(endpoint.Metadata.GetMetadata<IAllowAnonymous>());
        Assert.Equal("Registration_Register", endpoint.Metadata.GetMetadata<IEndpointNameMetadata>()?.EndpointName);
    }

    [Fact]
    public void VerificationMapping_UsesTheChosenDtoAndMapsOnlyVerificationRoutes() {
        using var host = CreateHost(includeVerificationDependencies: true);

        host.Endpoints.MapGroup("api/register")
            .MapVerificationApi<IdentityUser<int>, TestUserDto, int>();

        var endpoints = Endpoints(host).OfType<RouteEndpoint>().ToArray();
        Assert.Equal(new[] { "api/register/register/resend", "api/register/register/verify" },
            endpoints.Select(endpoint => endpoint.RoutePattern.RawText).OrderBy(route => route, StringComparer.Ordinal));
        Assert.All(endpoints, endpoint => Assert.IsAssignableFrom<IAllowAnonymous>(endpoint.Metadata.GetMetadata<IAllowAnonymous>()));
        Assert.Equal(2, endpoints.Select(endpoint => endpoint.Metadata.GetMetadata<IEndpointNameMetadata>()?.EndpointName).Distinct().Count());
    }

    [Fact]
    public void RegistrationMapping_ReportsMissingDependenciesAtMappingTime() {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IRegistrationService<IdentityUser<int>, int>>());
        services.AddSingleton(Mock.Of<IUserAccountService<IdentityUser<int>>>());
        services.AddSingleton(Mock.Of<IUserMapper<IdentityUser<int>, TestUserDto>>());
        using var host = new TestHost(services.BuildServiceProvider());

        var error = Assert.Throws<InvalidOperationException>(() => host.Endpoints
            .MapRegistrationApi<IdentityUser<int>, TestUserDto, int>());

        Assert.Contains("Registration", error.Message, StringComparison.Ordinal);
        Assert.Contains("IVerificationWorkflowService", error.Message, StringComparison.Ordinal);
        Assert.Contains("IVerificationRequestStore", error.Message, StringComparison.Ordinal);
        Assert.Contains("IVerificationSender", error.Message, StringComparison.Ordinal);
    }

    private static TestHost CreateHost(bool includeVerificationDependencies) {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IRegistrationService<IdentityUser<int>, int>>());
        services.AddSingleton(Mock.Of<IUserAccountService<IdentityUser<int>>>());
        services.AddSingleton(Mock.Of<IUserMapper<IdentityUser<int>, TestUserDto>>());
        if(includeVerificationDependencies) {
            services.AddSingleton(Mock.Of<IVerificationWorkflowService<IdentityUser<int>, int>>());
            services.AddSingleton(Mock.Of<IVerificationRequestStore<int>>());
            services.AddSingleton(Mock.Of<IVerificationSender<IdentityUser<int>, int>>());
        }
        return new TestHost(services.BuildServiceProvider());
    }

    private static Endpoint[] Endpoints(TestHost host) => host.Endpoints.DataSources
        .SelectMany(source => source.Endpoints).ToArray();

    public sealed class TestUserDto { }

    private sealed class TestHost : IDisposable {
        public TestHost(IServiceProvider services) => Endpoints = new TestEndpointRouteBuilder(services);
        public TestEndpointRouteBuilder Endpoints { get; }
        public void Dispose() => (Endpoints.ServiceProvider as IDisposable)?.Dispose();
    }

    private sealed class TestEndpointRouteBuilder : IEndpointRouteBuilder {
        public TestEndpointRouteBuilder(IServiceProvider services) => ServiceProvider = services;
        public ICollection<EndpointDataSource> DataSources { get; } = new List<EndpointDataSource>();
        public IServiceProvider ServiceProvider { get; }
        public IApplicationBuilder CreateApplicationBuilder() => new ApplicationBuilder(ServiceProvider);
    }
}
