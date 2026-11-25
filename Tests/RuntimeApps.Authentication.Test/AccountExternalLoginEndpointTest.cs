using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using RuntimeApps.Authentication.Endpoints.Account;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

/// <summary>HTTP contract of the authenticated external-login management endpoints.</summary>
public sealed class AccountExternalLoginEndpointTest {
    private readonly Mock<IExternalLoginService<IdentityUser<int>>> _service = new();
    private readonly Mock<IUserManager<IdentityUser<int>>> _userManager = new();
    private readonly IdentityUser<int> _user = new() { Id = 7 };

    public AccountExternalLoginEndpointTest() {
        _userManager.Setup(m => m.GetUserAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>())).ReturnsAsync(_user);
    }

    private IServiceProvider Services(bool includeExternalLoginService = true) {
        var services = new ServiceCollection();
        services.AddLogging().AddProblemDetails();
        services.AddSingleton(_userManager.Object);
        services.AddSingleton(Mock.Of<IUserMapper<IdentityUser<int>, Dto>>());
        services.AddSingleton(Mock.Of<IUserPasswordManager<IdentityUser<int>>>());
        if(includeExternalLoginService)
            services.AddSingleton(_service.Object);
        return services.BuildServiceProvider();
    }

    private static RouteEndpoint[] Map(IServiceProvider services) {
        var builder = new Builder(services);
        builder.MapGroup("api/account").MapAccountManagementApi<IdentityUser<int>, Dto, int>();
        return builder.DataSources.SelectMany(source => source.Endpoints).OfType<RouteEndpoint>().ToArray();
    }

    private static RouteEndpoint Route(RouteEndpoint[] endpoints, string route) =>
        endpoints.Single(endpoint => endpoint.RoutePattern.RawText == route);

    private static async Task<(int Status, string Body)> Send(RouteEndpoint endpoint, IServiceProvider services, string method, string json = null) {
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Method = method;
        if(json != null) {
            var bytes = Encoding.UTF8.GetBytes(json);
            context.Request.ContentType = "application/json";
            context.Request.Body = new MemoryStream(bytes);
            context.Request.ContentLength = bytes.Length;
            context.Features.Set<IHttpRequestBodyDetectionFeature>(new BodyFeature());
        }
        await using var response = new MemoryStream();
        context.Response.Body = response;
        await endpoint.RequestDelegate!(context);
        response.Position = 0;
        return (context.Response.StatusCode, await new StreamReader(response).ReadToEndAsync());
    }

    [Fact]
    public void ExternalLoginRoutes_AreMappedOnlyWhenTheServiceIsRegistered() {
        var unmapped = Map(Services(includeExternalLoginService: false)).Select(e => e.RoutePattern.RawText).ToArray();
        var mapped = Map(Services()).Select(e => e.RoutePattern.RawText).ToArray();

        Assert.DoesNotContain(unmapped, route => route.Contains("logins", StringComparison.Ordinal));
        Assert.Contains("api/account/logins", mapped);
        Assert.Contains("api/account/logins/link", mapped);
        Assert.Contains("api/account/logins/unlink", mapped);
    }

    [Fact]
    public void ExternalLoginRoutes_RequireAuthorizationAndDeclareErrorContracts() {
        var endpoints = Map(Services());

        foreach(var route in new[] { "api/account/logins", "api/account/logins/link", "api/account/logins/unlink" }) {
            var endpoint = Route(endpoints, route);
            Assert.NotEmpty(endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>());
            Assert.Null(endpoint.Metadata.GetMetadata<IAllowAnonymous>());
            var statuses = endpoint.Metadata.GetOrderedMetadata<Microsoft.AspNetCore.Http.Metadata.IProducesResponseTypeMetadata>()
                .Select(metadata => metadata.StatusCode).ToArray();
            Assert.Contains(StatusCodes.Status401Unauthorized, statuses);
            Assert.Contains(StatusCodes.Status403Forbidden, statuses);
        }

        var linkStatuses = Route(endpoints, "api/account/logins/link").Metadata
            .GetOrderedMetadata<Microsoft.AspNetCore.Http.Metadata.IProducesResponseTypeMetadata>().Select(m => m.StatusCode).ToArray();
        Assert.Contains(StatusCodes.Status409Conflict, linkStatuses);
        Assert.Contains(StatusCodes.Status400BadRequest, linkStatuses);
    }

    [Fact]
    public async Task List_ReturnsProvidersForCurrentAccount() {
        _service.Setup(s => s.ListLoginsAsync(_user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<ExternalLoginSummary> { new() { Provider = "GOOGLE" } });
        var services = Services();

        var response = await Send(Route(Map(services), "api/account/logins"), services, "GET");

        Assert.Equal(StatusCodes.Status200OK, response.Status);
        Assert.Contains("GOOGLE", response.Body);
    }

    [Fact]
    public async Task List_UnknownCurrentUser_Returns401() {
        _userManager.Setup(m => m.GetUserAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>())).ReturnsAsync((IdentityUser<int>)null);
        var services = Services();

        var response = await Send(Route(Map(services), "api/account/logins"), services, "GET");

        Assert.Equal(StatusCodes.Status401Unauthorized, response.Status);
        _service.Verify(s => s.ListLoginsAsync(It.IsAny<IdentityUser<int>>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Link_Success_Returns200() {
        _service.Setup(s => s.LinkAsync(_user, It.Is<LinkExternalLoginModel>(m => m.Provider == "MICROSOFT" && m.CurrentPassword == "pw"), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result());
        var services = Services();

        var response = await Send(Route(Map(services), "api/account/logins/link"), services, "POST",
            "{\"Provider\":\"MICROSOFT\",\"Token\":\"t\",\"CurrentPassword\":\"pw\"}");

        Assert.Equal(StatusCodes.Status200OK, response.Status);
    }

    [Fact]
    public async Task Link_MalformedBody_Returns400WithoutCallingService() {
        var services = Services();

        var response = await Send(Route(Map(services), "api/account/logins/link"), services, "POST", "{\"Provider\":\"\",\"Token\":\"t\"}");

        Assert.Equal(StatusCodes.Status400BadRequest, response.Status);
        Assert.Contains("InvalidExternalLogin", response.Body);
        _service.Verify(s => s.LinkAsync(It.IsAny<IdentityUser<int>>(), It.IsAny<LinkExternalLoginModel>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Theory]
    [InlineData(ResultCode.Forbidden, StatusCodes.Status403Forbidden)]
    [InlineData(ResultCode.Conflict, StatusCodes.Status409Conflict)]
    [InlineData(ResultCode.BadRequest, StatusCodes.Status400BadRequest)]
    public async Task Link_Failure_MapsToStatusWithoutInternalDetail(ResultCode code, int expectedStatus) {
        _service.Setup(s => s.LinkAsync(_user, It.IsAny<LinkExternalLoginModel>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result(code, Result.CreateErrors("InternalCode", "private internal detail")));
        var services = Services();

        var response = await Send(Route(Map(services), "api/account/logins/link"), services, "POST",
            "{\"Provider\":\"MICROSOFT\",\"Token\":\"t\",\"CurrentPassword\":\"pw\"}");

        Assert.Equal(expectedStatus, response.Status);
        Assert.DoesNotContain("private internal detail", response.Body);
        Assert.DoesNotContain("InternalCode", response.Body);
    }

    [Fact]
    public async Task Link_UnknownCurrentUser_Returns401() {
        _userManager.Setup(m => m.GetUserAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>())).ReturnsAsync((IdentityUser<int>)null);
        var services = Services();

        var response = await Send(Route(Map(services), "api/account/logins/link"), services, "POST",
            "{\"Provider\":\"MICROSOFT\",\"Token\":\"t\",\"CurrentPassword\":\"pw\"}");

        Assert.Equal(StatusCodes.Status401Unauthorized, response.Status);
    }

    [Fact]
    public async Task Unlink_Success_Returns200() {
        _service.Setup(s => s.UnlinkAsync(_user, "GOOGLE", It.IsAny<CancellationToken>())).ReturnsAsync(new Result());
        var services = Services();

        var response = await Send(Route(Map(services), "api/account/logins/unlink"), services, "POST", "{\"Provider\":\"GOOGLE\"}");

        Assert.Equal(StatusCodes.Status200OK, response.Status);
    }

    [Fact]
    public async Task Unlink_LastAuthenticationMethod_Returns409WithoutInternalDetail() {
        _service.Setup(s => s.UnlinkAsync(_user, "GOOGLE", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result(ResultCode.Conflict, Result.CreateErrors("LastAuthenticationMethod", "private detail")));
        var services = Services();

        var response = await Send(Route(Map(services), "api/account/logins/unlink"), services, "POST", "{\"Provider\":\"GOOGLE\"}");

        Assert.Equal(StatusCodes.Status409Conflict, response.Status);
        Assert.DoesNotContain("private detail", response.Body);
    }

    [Fact]
    public async Task Unlink_MalformedBody_Returns400() {
        var services = Services();

        var response = await Send(Route(Map(services), "api/account/logins/unlink"), services, "POST", "{\"Provider\":\" \"}");

        Assert.Equal(StatusCodes.Status400BadRequest, response.Status);
        _service.Verify(s => s.UnlinkAsync(It.IsAny<IdentityUser<int>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    public sealed class Dto { }

    private sealed class BodyFeature : IHttpRequestBodyDetectionFeature {
        public bool CanHaveBody => true;
    }

    private sealed class Builder(IServiceProvider services) : IEndpointRouteBuilder {
        public ICollection<EndpointDataSource> DataSources { get; } = new List<EndpointDataSource>();
        public IServiceProvider ServiceProvider { get; } = services;
        public IApplicationBuilder CreateApplicationBuilder() => new ApplicationBuilder(ServiceProvider);
    }
}
