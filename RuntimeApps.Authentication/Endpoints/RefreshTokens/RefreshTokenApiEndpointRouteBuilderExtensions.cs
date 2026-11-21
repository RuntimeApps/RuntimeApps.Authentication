using System.Net.Http.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Features.RefreshTokens.Services;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;
namespace RuntimeApps.Authentication.Endpoints.RefreshTokens {
    public static class RefreshTokenApiEndpointRouteBuilderExtensions {
        /// <summary>
        /// Maps refresh, current-session logout, and logout-all endpoints.
        /// </summary>
        public static IEndpointRouteBuilder MapSessionApi<TUser, TKey>(this IEndpointRouteBuilder endpoints)
            where TUser : IdentityUser<TKey>
            where TKey : IEquatable<TKey> {
            var availability = endpoints.ServiceProvider.GetService<IServiceProviderIsService>();
            if(availability?.IsService(typeof(IRefreshTokenService<TKey>)) != true)
                throw new InvalidOperationException("Session endpoints require the refresh-token service. Register refresh-token functionality first.");
            if(availability.IsService(typeof(IAuthenticationSessionIssuer<TUser>)) != true)
                throw new InvalidOperationException("Session endpoints require exactly one explicitly registered authentication session issuer.");

            var routes = endpoints.MapGroup("");

            routes.MapPost("refresh", async Task<IResult> (HttpContext context,
                IUserManager<TUser> userManager,
                IUserLockoutManager<TUser> lockoutManager,
                IUserLoginManager<TUser> loginManager,
                ISignInManager<TUser> signInManager,
                IUserClaimsPrincipalFactory<TUser> principalFactory,
                IRefreshTokenService<TKey> refreshTokenService,
                IRefreshTokenRequestLimiter requestLimiter,
                IServiceProvider services,
                IEnumerable<IAuthenticationSessionIssuer<TUser>> sessionIssuers,
                IOptions<RefreshTokenOptions> options,
                IOptions<CookieSessionOptions> cookieOptions,
                IOptions<VerificationOptions> verificationOptions) => {
                    if(!await requestLimiter.IsAllowedAsync(context, context.RequestAborted))
                        return Results.StatusCode(StatusCodes.Status429TooManyRequests);

                    var mode = GetSessionMode(sessionIssuers);
                    var isCookie = mode == AuthenticationSessionMode.Cookie;
                    RefreshTokenRequest request = null;
                    if(!isCookie && context.Request.HasJsonContentType())
                        request = await context.Request.ReadFromJsonAsync<RefreshTokenRequest>(context.RequestAborted);
                    if(isCookie && !IsAllowedOrigin(context, options.Value))
                        return Results.StatusCode(StatusCodes.Status403Forbidden);

                    var suppliedToken = isCookie
                        ? context.Request.Cookies[options.Value.CookieName]
                        : request?.RefreshToken;

                    var session = await refreshTokenService.RotateAsync(suppliedToken, context.RequestAborted);
                    if(session == null)
                        return Results.Unauthorized();

                    var user = await userManager.FindByIdAsync(Convert.ToString(session.UserId, System.Globalization.CultureInfo.InvariantCulture));
                    if(user == null) {
                        await refreshTokenService.RevokeAsync(session.RefreshToken, context.RequestAborted);
                        return Results.Unauthorized();
                    }

                    var isLockedOut = await lockoutManager.IsLockedOutAsync(user);
                    var hasExternalLogin = (await loginManager.GetLoginsAsync(user)).Count > 0;
                    var emailPolicyAllowsSignIn = user.EmailConfirmed ||
                        (hasExternalLogin && !verificationOptions.Value.RequireEmailVerificationForExternalLogins);
                    if(isLockedOut || !emailPolicyAllowsSignIn ||
                       (user.EmailConfirmed && !await signInManager.CanSignInAsync(user))) {
                        await refreshTokenService.RevokeAsync(session.RefreshToken, context.RequestAborted);
                        return Results.Unauthorized();
                    }

                    try {
                        if(isCookie) {
                            var principal = await principalFactory.CreateAsync(user);
                            await context.SignInAsync(cookieOptions.Value.Scheme, principal,
                                new AuthenticationProperties { IsPersistent = cookieOptions.Value.IsPersistent });
                            AppendRefreshCookie(context, options.Value, session.RefreshToken, session.ExpiresAt);
                            return Results.NoContent();
                        }

                        var jwtProvider = services.GetService<IJwtProvider<TUser>>();
                        if(jwtProvider == null) {
                            await refreshTokenService.RevokeAsync(session.RefreshToken, CancellationToken.None);
                            return Results.Problem("JWT authentication is not configured.", statusCode: StatusCodes.Status500InternalServerError);
                        }

                        var accessToken = await jwtProvider.GenerateTokenAsync(user, context.RequestAborted);
                        accessToken.RefreshToken = session.RefreshToken;
                        accessToken.RefreshTokenExpireDate = session.ExpiresAt;
                        accessToken.SessionId = session.SessionId;
                        return Results.Ok(accessToken);
                    } catch {
                        await refreshTokenService.RevokeAsync(session.RefreshToken, CancellationToken.None);
                        throw;
                    }
                })
            .Accepts<RefreshTokenRequest>(true, "application/json")
            .AllowAnonymous()
            .WithName("Session_Refresh")
            .WithTags("Sessions")
            .WithSummary("Refresh the current session")
            .WithDescription("JWT clients send a RefreshTokenRequest JSON body. Cookie clients send the refresh-token cookie; the JSON body is optional for cookie authentication.");

            routes.MapPost("logout", async Task<IResult> (HttpContext context,
                IRefreshTokenService<TKey> refreshTokenService,
                IOptions<RefreshTokenOptions> options,
                IOptions<CookieSessionOptions> cookieOptions,
                IEnumerable<IAuthenticationSessionIssuer<TUser>> sessionIssuers) => {
                    var isCookie = GetSessionMode(sessionIssuers) == AuthenticationSessionMode.Cookie;
                    RefreshTokenRequest request = null;
                    if(!isCookie && context.Request.HasJsonContentType())
                        request = await context.Request.ReadFromJsonAsync<RefreshTokenRequest>(context.RequestAborted);
                    if(isCookie && !IsAllowedOrigin(context, options.Value))
                        return Results.StatusCode(StatusCodes.Status403Forbidden);

                    var token = isCookie
                        ? context.Request.Cookies[options.Value.CookieName]
                        : request?.RefreshToken;
                    await refreshTokenService.RevokeAsync(token, context.RequestAborted);
                    if(isCookie)
                        await context.SignOutAsync(cookieOptions.Value.Scheme);
                    if(isCookie)
                        DeleteRefreshCookie(context, options.Value);
                    return Results.NoContent();
                })
            .Accepts<RefreshTokenRequest>(true, "application/json")
            .AllowAnonymous()
            .WithName("Session_Logout")
            .WithTags("Sessions")
            .WithSummary("Log out the current session")
            .WithDescription("JWT clients send a RefreshTokenRequest JSON body. Cookie clients send the refresh-token cookie; the JSON body is optional for cookie authentication.");

            routes.MapPost("logout/all", async Task<IResult> (HttpContext context,
                IUserManager<TUser> userManager,
                IRefreshTokenService<TKey> refreshTokenService,
                IOptions<RefreshTokenOptions> options,
                IOptions<CookieSessionOptions> cookieOptions,
                IEnumerable<IAuthenticationSessionIssuer<TUser>> sessionIssuers) => {
                    var isCookie = GetSessionMode(sessionIssuers) == AuthenticationSessionMode.Cookie;
                    var user = await userManager.GetUserAsync(context.User);
                    if(user == null)
                        return Results.Unauthorized();

                    if(isCookie && !IsAllowedOrigin(context, options.Value))
                        return Results.StatusCode(StatusCodes.Status403Forbidden);

                    await refreshTokenService.RevokeAllAsync(user.Id, context.RequestAborted);
                    if(isCookie)
                        await context.SignOutAsync(cookieOptions.Value.Scheme);
                    if(isCookie)
                        DeleteRefreshCookie(context, options.Value);
                    return Results.NoContent();
                }).RequireAuthorization().WithName("Session_LogoutAll").WithTags("Sessions").WithSummary("Log out all sessions");

            return endpoints;
        }

        private static AuthenticationSessionMode GetSessionMode<TUser>(IEnumerable<IAuthenticationSessionIssuer<TUser>> issuers) where TUser : class {
            var registered = issuers.Take(2).ToArray();
            if(registered.Length != 1)
                throw new InvalidOperationException("Refresh-token endpoints require exactly one explicitly registered authentication session issuer.");
            if(registered[0].Mode is not (AuthenticationSessionMode.Jwt or AuthenticationSessionMode.Cookie))
                throw new InvalidOperationException("The registered authentication session issuer must explicitly select JWT or cookie mode.");
            return registered[0].Mode;
        }

        private static void DeleteRefreshCookie(HttpContext context, RefreshTokenOptions options) => context.Response.Cookies.Delete(options.CookieName, new CookieOptions {
            Path = options.CookiePath,
            Secure = options.CookieSecure,
            HttpOnly = true,
            SameSite = options.CookieSameSite
        });

        private static bool IsAllowedOrigin(HttpContext context, RefreshTokenOptions options) {
            var origin = context.Request.Headers["Origin"].ToString();
            if(!Uri.TryCreate(origin, UriKind.Absolute, out var originUri) ||
               (originUri.Scheme != Uri.UriSchemeHttp && originUri.Scheme != Uri.UriSchemeHttps) ||
               originUri.AbsolutePath != "/" || !string.IsNullOrEmpty(originUri.Query) ||
               !string.IsNullOrEmpty(originUri.Fragment))
                return false;

            var normalizedOrigin = originUri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
            var requestOrigin = $"{context.Request.Scheme}://{context.Request.Host}".TrimEnd('/');
            if(string.Equals(normalizedOrigin, requestOrigin, StringComparison.OrdinalIgnoreCase))
                return true;

            return options.AllowedOrigins?.Any(allowed =>
                string.Equals(allowed?.TrimEnd('/'), normalizedOrigin, StringComparison.OrdinalIgnoreCase)) == true;
        }

        private static void AppendRefreshCookie(
            HttpContext context,
            RefreshTokenOptions options,
            string refreshToken,
            DateTimeOffset expiresAt) {
            context.Response.Cookies.Append(options.CookieName, refreshToken, new CookieOptions {
                HttpOnly = true,
                Secure = options.CookieSecure,
                SameSite = options.CookieSameSite,
                Path = options.CookiePath,
                Expires = expiresAt
            });
        }
    }
}
