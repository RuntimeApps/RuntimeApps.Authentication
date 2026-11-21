using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moq;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.Endpoints.RefreshTokens;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

public sealed class RefreshTokenEndpointModeTest {
    private const string JwtDefaultScheme = "default-cookie";
    private const string CookieDefaultScheme = "default-jwt";
    private const string CookieSessionScheme = "app-cookie";
    private const string OldRefreshToken = "old-refresh-token";
    private const string NewRefreshToken = "new-refresh-token";

    [Fact]
    public async Task JwtRefresh_UsesBodyAndReturnsJwt_EvenWhenDefaultSignInIsCookie() {
        var user = NewUser();
        var refresh = NewRefreshService(user);
        var jwt = new Mock<IJwtProvider<IdentityUser>>();
        jwt.Setup(provider => provider.GenerateTokenAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Token { AuthenticationToken = "access-token" });
        using var app = CreateApp(AuthenticationSessionMode.Jwt, refresh.Object, jwt.Object);
        var context = NewRequest(app, "refresh", OldRefreshToken, asJson: true);

        await InvokeAsync(app, "refresh", context);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("Set-Cookie"));
        context.Response.Body.Position = 0;
        var response = await JsonSerializer.DeserializeAsync<Token>(context.Response.Body, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Equal("access-token", response?.AuthenticationToken);
        Assert.Equal(NewRefreshToken, response?.RefreshToken);
        refresh.Verify(service => service.RotateAsync(OldRefreshToken, It.IsAny<CancellationToken>()), Times.Once);
        jwt.Verify(provider => provider.GenerateTokenAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task CookieRefresh_UsesConfiguredCookieScheme_EvenWhenDefaultSignInIsJwt() {
        var user = NewUser();
        var refresh = NewRefreshService(user);
        using var app = CreateApp(AuthenticationSessionMode.Cookie, refresh.Object);
        var context = NewRequest(app, "refresh", OldRefreshToken, asJson: false);

        await InvokeAsync(app, "refresh", context);

        Assert.Equal(StatusCodes.Status204NoContent, context.Response.StatusCode);
        var setCookie = context.Response.Headers.SetCookie.ToString();
        Assert.Contains("app-cookie=", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("__Host-runtimeapps-refresh=" + NewRefreshToken, setCookie, StringComparison.Ordinal);
        Assert.DoesNotContain("default-cookie=", setCookie, StringComparison.OrdinalIgnoreCase);
        refresh.Verify(service => service.RotateAsync(OldRefreshToken, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task JwtLogout_RevokesBodyCredentialWithoutCookieOperations() {
        var refresh = NewRefreshService(NewUser());
        refresh.Setup(service => service.RevokeAsync(OldRefreshToken, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        using var app = CreateApp(AuthenticationSessionMode.Jwt, refresh.Object);
        var context = NewRequest(app, "logout", OldRefreshToken, asJson: true);

        await InvokeAsync(app, "logout", context);

        Assert.Equal(StatusCodes.Status204NoContent, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("Set-Cookie"));
        refresh.Verify(service => service.RevokeAsync(OldRefreshToken, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task CookieLogout_RevokesCookieAndSignsOutConfiguredScheme() {
        var refresh = NewRefreshService(NewUser());
        refresh.Setup(service => service.RevokeAsync(OldRefreshToken, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        using var app = CreateApp(AuthenticationSessionMode.Cookie, refresh.Object);
        var context = NewRequest(app, "logout", OldRefreshToken, asJson: false);

        await InvokeAsync(app, "logout", context);

        Assert.Equal(StatusCodes.Status204NoContent, context.Response.StatusCode);
        var setCookie = context.Response.Headers.SetCookie.ToString();
        Assert.Contains("app-cookie=", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("__Host-runtimeapps-refresh=", setCookie, StringComparison.Ordinal);
        Assert.DoesNotContain("default-cookie=", setCookie, StringComparison.OrdinalIgnoreCase);
        refresh.Verify(service => service.RevokeAsync(OldRefreshToken, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task JwtLogoutAll_RevokesAllWithoutCookieOperations() {
        var user = NewUser();
        var refresh = NewRefreshService(user);
        refresh.Setup(service => service.RevokeAllAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(2);
        using var app = CreateApp(AuthenticationSessionMode.Jwt, refresh.Object);
        var context = NewRequest(app, "logout/all", null, asJson: false);
        context.User = PrincipalFor(user);

        await InvokeAsync(app, "logout/all", context);

        Assert.Equal(StatusCodes.Status204NoContent, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("Set-Cookie"));
        refresh.Verify(service => service.RevokeAllAsync(user.Id, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task CookieLogoutAll_RevokesAllAndSignsOutConfiguredScheme() {
        var user = NewUser();
        var refresh = NewRefreshService(user);
        refresh.Setup(service => service.RevokeAllAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(2);
        using var app = CreateApp(AuthenticationSessionMode.Cookie, refresh.Object);
        var context = NewRequest(app, "logout/all", null, asJson: false);
        context.User = PrincipalFor(user);

        await InvokeAsync(app, "logout/all", context);

        Assert.Equal(StatusCodes.Status204NoContent, context.Response.StatusCode);
        var setCookie = context.Response.Headers.SetCookie.ToString();
        Assert.Contains("app-cookie=", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("__Host-runtimeapps-refresh=", setCookie, StringComparison.Ordinal);
        Assert.DoesNotContain("default-cookie=", setCookie, StringComparison.OrdinalIgnoreCase);
        refresh.Verify(service => service.RevokeAllAsync(user.Id, It.IsAny<CancellationToken>()), Times.Once);
    }

    private static EndpointHost CreateApp(
        AuthenticationSessionMode mode,
        IRefreshTokenService<string> refreshService,
        IJwtProvider<IdentityUser> jwtProvider = null) {
        var services = new ServiceCollection();
        var wrongDefault = mode == AuthenticationSessionMode.Jwt ? JwtDefaultScheme : CookieDefaultScheme;
        var authentication = services.AddAuthentication(options => {
            options.DefaultAuthenticateScheme = wrongDefault;
            options.DefaultChallengeScheme = wrongDefault;
            options.DefaultSignInScheme = wrongDefault;
        });
        authentication.AddCookie(JwtDefaultScheme, options => options.Cookie.Name = "default-cookie");
        authentication.AddJwtBearer(CookieDefaultScheme);
        authentication.AddCookie(CookieSessionScheme, options => options.Cookie.Name = "app-cookie");
        services.AddLogging();
        services.AddDataProtection().UseEphemeralDataProtectionProvider();

        var runtime = authentication.AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();
        runtime.AddRefreshToken();
        if(mode == AuthenticationSessionMode.Jwt)
            runtime.UseJwt("jwt", _ => { });
        else
            runtime.AddCookieAuthenticationSessionIssuer(options => options.Scheme = CookieSessionScheme);

        var user = NewUser();
        var principal = PrincipalFor(user);
        var userManager = new Mock<IUserManager<IdentityUser>>();
        userManager.Setup(manager => manager.FindByIdAsync(user.Id)).ReturnsAsync(user);
        userManager.Setup(manager => manager.GetUserAsync(It.IsAny<ClaimsPrincipal>())).ReturnsAsync(user);
        var lockout = new Mock<IUserLockoutManager<IdentityUser>>();
        lockout.Setup(manager => manager.IsLockedOutAsync(user)).ReturnsAsync(false);
        var logins = new Mock<IUserLoginManager<IdentityUser>>();
        logins.Setup(manager => manager.GetLoginsAsync(user)).ReturnsAsync(new List<UserLoginInfo>());
        var signIn = new Mock<ISignInManager<IdentityUser>>();
        signIn.Setup(manager => manager.CanSignInAsync(user)).ReturnsAsync(true);
        var principalFactory = new Mock<IUserClaimsPrincipalFactory<IdentityUser>>();
        principalFactory.Setup(factory => factory.CreateAsync(user)).ReturnsAsync(principal);

        services.Replace(ServiceDescriptor.Singleton<IUserManager<IdentityUser>>(userManager.Object));
        services.Replace(ServiceDescriptor.Singleton<IUserLockoutManager<IdentityUser>>(lockout.Object));
        services.Replace(ServiceDescriptor.Singleton<IUserLoginManager<IdentityUser>>(logins.Object));
        services.Replace(ServiceDescriptor.Singleton<ISignInManager<IdentityUser>>(signIn.Object));
        services.Replace(ServiceDescriptor.Singleton<IUserClaimsPrincipalFactory<IdentityUser>>(principalFactory.Object));
        services.Replace(ServiceDescriptor.Singleton<IRefreshTokenService<string>>(refreshService));
        if(jwtProvider != null)
            services.Replace(ServiceDescriptor.Singleton<IJwtProvider<IdentityUser>>(jwtProvider));

        var serviceProvider = services.BuildServiceProvider();
        var endpoints = new TestEndpointRouteBuilder(serviceProvider);
        endpoints.MapRefreshTokenApi<IdentityUser, string>();
        return new EndpointHost(serviceProvider, endpoints);
    }

    private static Mock<IRefreshTokenService<string>> NewRefreshService(IdentityUser user) {
        var refresh = new Mock<IRefreshTokenService<string>>();
        refresh.Setup(service => service.RotateAsync(OldRefreshToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RefreshTokenSession<string> {
                UserId = user.Id,
                SessionId = Guid.NewGuid(),
                RefreshToken = NewRefreshToken,
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(1)
            });
        return refresh;
    }

    private static IdentityUser NewUser() => new() { Id = "user-1", EmailConfirmed = true };

    private static ClaimsPrincipal PrincipalFor(IdentityUser user) => new(new ClaimsIdentity(
        new[] { new Claim(ClaimTypes.NameIdentifier, user.Id) }, "test"));

    private static DefaultHttpContext NewRequest(EndpointHost app, string path, string refreshToken, bool asJson) {
        var context = new DefaultHttpContext { RequestServices = app.Services };
        context.Request.Method = "POST";
        context.Request.Path = "/" + path;
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("api.example.test");
        context.Response.Body = new MemoryStream();
        if(refreshToken != null) {
            if(asJson) {
                context.Request.ContentType = "application/json";
                context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new RefreshTokenRequest { RefreshToken = refreshToken })));
            } else {
                context.Request.Headers.Cookie = "__Host-runtimeapps-refresh=" + refreshToken;
                context.Request.Headers.Origin = "https://api.example.test";
            }
        } else if(path == "logout/all") {
            context.Request.Headers.Origin = "https://api.example.test";
        }
        return context;
    }

    private static async Task InvokeAsync(EndpointHost app, string route, HttpContext context) {
        var endpoint = app.Endpoints.DataSources.SelectMany(source => source.Endpoints).OfType<RouteEndpoint>()
            .Single(candidate => string.Equals(candidate.RoutePattern.RawText?.Trim('/'), route, StringComparison.OrdinalIgnoreCase));
        context.SetEndpoint(endpoint);
        var requestDelegate = endpoint.RequestDelegate ?? throw new InvalidOperationException("Mapped endpoint has no request delegate.");
        await requestDelegate(context);
    }

    private sealed class EndpointHost : IDisposable {
        public EndpointHost(IServiceProvider services, TestEndpointRouteBuilder endpoints) {
            Services = services;
            Endpoints = endpoints;
        }

        public IServiceProvider Services { get; }
        public TestEndpointRouteBuilder Endpoints { get; }
        public void Dispose() => (Services as IDisposable)?.Dispose();
    }

    private sealed class TestEndpointRouteBuilder : IEndpointRouteBuilder {
        public TestEndpointRouteBuilder(IServiceProvider services) => ServiceProvider = services;

        public ICollection<EndpointDataSource> DataSources { get; } = new List<EndpointDataSource>();
        public IServiceProvider ServiceProvider { get; }
        public IApplicationBuilder CreateApplicationBuilder() => new ApplicationBuilder(ServiceProvider);
    }
}
