using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using RuntimeApps.Authentication.Endpoints.Roles;
using RuntimeApps.Authentication.Endpoints.Roles.Models;
using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

public sealed class PublicRequestContractTest {
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);
    [Fact]
    public void UserRolesRequest_UsesNamedCollectionProperty() {
        var request = JsonSerializer.Deserialize<UserRolesRequest>("""{"roles":["Admin","Auditor"]}""", WebJson);

        Assert.Equal(new[] { "Admin", "Auditor" }, request?.Roles);
    }

    [Fact]
    public void BulkClaimsRequest_UsesNamedCollectionProperty() {
        var request = JsonSerializer.Deserialize<BulkClaimsRequest>("""{"claims":[{"type":"department","value":"finance"}]}""", WebJson);

        var claim = Assert.Single(request!.Claims);
        Assert.Equal("department", claim.Type);
        Assert.Equal("finance", claim.Value);
    }

    [Fact]
    public void RoleRequest_PreservesConsumerSpecificRoleFieldsInsideNamedEnvelope() {
        var request = JsonSerializer.Deserialize<RoleRequest<TestRole>>("""{"role":{"name":"Admin","displayName":"Administrators"}}""", WebJson);

        Assert.NotNull(request);
        Assert.Equal("Admin", request.Role.Name);
        Assert.Equal("Administrators", request.Role.DisplayName);
    }

    [Fact]
    public void RoleManagementEndpointMetadata_DeclaresRoleRequestSchema() {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddSingleton(Mock.Of<IRoleManager<IdentityRole>>());
        var services = serviceCollection.BuildServiceProvider();
        var endpoints = new TestEndpointRouteBuilder(services);
        endpoints.MapRoleManageApi<IdentityRole>();
        var endpoint = Assert.Single(endpoints.DataSources.SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>().Where(item => item.RoutePattern.RawText == "/" &&
                item.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods.Contains("POST") == true));

        Assert.Contains(endpoint.Metadata.GetOrderedMetadata<IAcceptsMetadata>(), metadata =>
            metadata.RequestType == typeof(RoleRequest<IdentityRole>));
        Assert.Contains(endpoint.Metadata.GetOrderedMetadata<IProducesResponseTypeMetadata>(), metadata =>
            metadata.StatusCode == StatusCodes.Status200OK);
    }

    public sealed class TestRole {
        public string Name { get; set; }
        public string DisplayName { get; set; }
    }

    private sealed class TestEndpointRouteBuilder : IEndpointRouteBuilder {
        public TestEndpointRouteBuilder(IServiceProvider services) => ServiceProvider = services;
        public ICollection<EndpointDataSource> DataSources { get; } = new List<EndpointDataSource>();
        public IServiceProvider ServiceProvider { get; }
        public IApplicationBuilder CreateApplicationBuilder() => new ApplicationBuilder(ServiceProvider);
    }
}
