using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Features.Account.Services;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

public class AuthenticationSessionIssuerTest {
    [Fact]
    public async Task JwtIssuer_GeneratesTokenAndAddsRefreshSession() {
        var user = new IdentityUser { Id = "u1" };
        var expected = new Token { AuthenticationToken = "access" };
        var jwt = new Mock<IJwtProvider<IdentityUser>>();
        jwt.Setup(p => p.GenerateTokenAsync(user, It.IsAny<CancellationToken>())).ReturnsAsync(expected);
        var refresh = new Mock<IRefreshTokenService<string>>();
        refresh.Setup(s => s.CreateSessionAsync("u1", null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RefreshTokenSession<string> { UserId = "u1", SessionId = Guid.NewGuid(), RefreshToken = "refresh", ExpiresAt = DateTimeOffset.UtcNow.AddDays(1) });
        var issuer = new JwtAuthenticationSessionIssuer<IdentityUser, string>(jwt.Object, refresh.Object);

        var result = await issuer.IssueAsync(user);

        Assert.Same(expected, result);
        Assert.Equal("refresh", result.RefreshToken);
        Assert.NotNull(result.SessionId);
    }

    [Fact]
    public async Task JwtIssuer_PropagatesCancellationAndDoesNotIssue() {
        var jwt = new Mock<IJwtProvider<IdentityUser>>();
        var issuer = new JwtAuthenticationSessionIssuer<IdentityUser, string>(jwt.Object);
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => issuer.IssueAsync(new IdentityUser(), cancellation.Token));
        jwt.Verify(p => p.GenerateTokenAsync(It.IsAny<IdentityUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task JwtIssuer_PropagatesCancellationToProviderAndRefreshService() {
        using var cancellation = new CancellationTokenSource();
        var user = new IdentityUser { Id = "u1" };
        var jwt = new Mock<IJwtProvider<IdentityUser>>();
        jwt.Setup(p => p.GenerateTokenAsync(user, cancellation.Token)).ReturnsAsync(new Token());
        var refresh = new Mock<IRefreshTokenService<string>>();
        refresh.Setup(s => s.CreateSessionAsync("u1", null, cancellation.Token))
            .ReturnsAsync(new RefreshTokenSession<string> { UserId = "u1", RefreshToken = "r", ExpiresAt = DateTimeOffset.UtcNow.AddDays(1) });
        var issuer = new JwtAuthenticationSessionIssuer<IdentityUser, string>(jwt.Object, refresh.Object);

        await issuer.IssueAsync(user, cancellation.Token);

        jwt.Verify(p => p.GenerateTokenAsync(user, cancellation.Token), Times.Once);
        refresh.Verify(s => s.CreateSessionAsync("u1", null, cancellation.Token), Times.Once);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CookieIssuer_UsesExplicitPersistence(bool persistent) {
        var user = new IdentityUser();
        var principal = new ClaimsPrincipal(new ClaimsIdentity("test"));
        var principalFactory = new Mock<IUserClaimsPrincipalFactory<IdentityUser>>();
        principalFactory.Setup(f => f.CreateAsync(user)).ReturnsAsync(principal);
        var auth = new Mock<IAuthenticationService>();
        auth.Setup(a => a.SignInAsync(It.IsAny<HttpContext>(), "app-cookie", principal, It.IsAny<AuthenticationProperties>())).Returns(Task.CompletedTask);
        var services = new ServiceCollection().AddSingleton(auth.Object).BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        var accessor = new HttpContextAccessor { HttpContext = context };
        var cookieOptions = persistent
            ? new CookieSessionOptions { IsPersistent = true, Scheme = "app-cookie" }
            : new CookieSessionOptions { Scheme = "app-cookie" };
        var issuer = new CookieAuthenticationSessionIssuer<IdentityUser, string>(principalFactory.Object, accessor,
            Options.Create(cookieOptions));

        await issuer.IssueAsync(user);

        auth.Verify(a => a.SignInAsync(context, "app-cookie", principal,
            It.Is<AuthenticationProperties>(properties => properties.IsPersistent == persistent)), Times.Once);
    }

    [Fact]
    public async Task CookieIssuer_CreatesRefreshSessionBeforeEstablishingCookie() {
        var user = new IdentityUser { Id = "u1" };
        var principalFactory = new Mock<IUserClaimsPrincipalFactory<IdentityUser>>();
        principalFactory.Setup(f => f.CreateAsync(user)).ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity("test")));
        var refresh = new Mock<IRefreshTokenService<string>>();
        refresh.Setup(s => s.CreateSessionAsync("u1", null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RefreshTokenSession<string> { UserId = "u1", RefreshToken = "refresh", ExpiresAt = DateTimeOffset.UtcNow.AddDays(1) });
        var auth = new Mock<IAuthenticationService>();
        auth.Setup(a => a.SignInAsync(It.IsAny<HttpContext>(), "app-cookie", It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
            .Returns(Task.CompletedTask);
        var services = new ServiceCollection().AddSingleton(auth.Object).BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        var issuer = new CookieAuthenticationSessionIssuer<IdentityUser, string>(principalFactory.Object,
            new HttpContextAccessor { HttpContext = context }, Options.Create(new CookieSessionOptions { Scheme = "app-cookie" }), refresh.Object);

        await issuer.IssueAsync(user);

        auth.Verify(a => a.SignInAsync(context, "app-cookie", It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()), Times.Once);
        Assert.Contains("__Host-runtimeapps-refresh=refresh", context.Response.Headers.SetCookie.ToString());
    }

    [Fact]
    public async Task CookieIssuer_RefreshCreationFailureDoesNotEstablishCookie() {
        var user = new IdentityUser { Id = "u1" };
        var factory = new Mock<IUserClaimsPrincipalFactory<IdentityUser>>();
        factory.Setup(f => f.CreateAsync(user)).ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity("test")));
        var refresh = new Mock<IRefreshTokenService<string>>();
        refresh.Setup(s => s.CreateSessionAsync("u1", null, It.IsAny<CancellationToken>())).ThrowsAsync(new InvalidOperationException("store failure"));
        var auth = new Mock<IAuthenticationService>();
        var services = new ServiceCollection().AddSingleton(auth.Object).BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        var issuer = new CookieAuthenticationSessionIssuer<IdentityUser, string>(factory.Object,
            new HttpContextAccessor { HttpContext = context }, Options.Create(new CookieSessionOptions { Scheme = "app-cookie" }), refresh.Object);

        await Assert.ThrowsAsync<InvalidOperationException>(() => issuer.IssueAsync(user));
        auth.Verify(a => a.SignInAsync(It.IsAny<HttpContext>(), It.IsAny<string>(), It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()), Times.Never);
    }

    [Fact]
    public async Task CookieIssuer_SignInFailureRevokesNewRefreshCredential() {
        var user = new IdentityUser { Id = "u1" };
        var factory = new Mock<IUserClaimsPrincipalFactory<IdentityUser>>();
        factory.Setup(f => f.CreateAsync(user)).ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity("test")));
        var refresh = new Mock<IRefreshTokenService<string>>();
        refresh.Setup(s => s.CreateSessionAsync("u1", null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RefreshTokenSession<string> { UserId = "u1", RefreshToken = "new-refresh", ExpiresAt = DateTimeOffset.UtcNow.AddDays(1) });
        refresh.Setup(s => s.RevokeAsync("new-refresh", CancellationToken.None)).ReturnsAsync(true);
        var auth = new Mock<IAuthenticationService>();
        auth.Setup(a => a.SignInAsync(It.IsAny<HttpContext>(), "app-cookie", It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
            .ThrowsAsync(new InvalidOperationException("cookie failure"));
        var services = new ServiceCollection().AddSingleton(auth.Object).BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        var issuer = new CookieAuthenticationSessionIssuer<IdentityUser, string>(factory.Object,
            new HttpContextAccessor { HttpContext = context }, Options.Create(new CookieSessionOptions { Scheme = "app-cookie" }), refresh.Object);

        await Assert.ThrowsAsync<InvalidOperationException>(() => issuer.IssueAsync(user));
        refresh.Verify(s => s.RevokeAsync("new-refresh", CancellationToken.None), Times.Once);
        Assert.False(context.Response.Headers.ContainsKey("Set-Cookie"));
    }

    [Fact]
    public void CookieSessionPersistence_DefaultsToFalse() => Assert.False(new CookieSessionOptions().IsPersistent);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CookieIssuer_ProducesSessionOrPersistentCookie(bool persistent) {
        var options = new CookieSessionOptions { Scheme = "app-cookie", IsPersistent = persistent };
        var principalFactory = new Mock<IUserClaimsPrincipalFactory<IdentityUser>>();
        principalFactory.Setup(factory => factory.CreateAsync(It.IsAny<IdentityUser>()))
            .ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, "user") }, "test")));
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddAuthentication(options.Scheme).AddCookie(options.Scheme);
        using var serviceProvider = services.BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = serviceProvider };
        var issuer = new CookieAuthenticationSessionIssuer<IdentityUser, string>(principalFactory.Object,
            new HttpContextAccessor { HttpContext = context }, Options.Create(options));

        await issuer.IssueAsync(new IdentityUser());

        var setCookie = Assert.Single(context.Response.Headers.SetCookie.ToArray());
        Assert.Equal(persistent, setCookie.Contains("expires=", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void IssuerRegistration_IsExplicitAndRejectsConflict() {
        var services = new ServiceCollection();
        var builder = services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();
        Assert.False(services.Any(d => d.ServiceType == typeof(IAuthenticationSessionIssuer<IdentityUser>)));
        builder.AddCookieAuthenticationSessionIssuer();
        Assert.Single(services.Where(d => d.ServiceType == typeof(IAuthenticationSessionIssuer<IdentityUser>)));
        Assert.Throws<InvalidOperationException>(() => builder.AddJwtAuthenticationSessionIssuer());
    }

    [Fact]
    public void JwtUse_ExplicitlyRegistersJwtIssuer() {
        var services = new ServiceCollection();
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
            .UseJwt("jwt", options => { });
        Assert.Contains(services, descriptor => descriptor.ServiceType == typeof(IAuthenticationSessionIssuer<IdentityUser>) &&
            descriptor.ImplementationType == typeof(JwtAuthenticationSessionIssuer<IdentityUser, string>));
    }
}
