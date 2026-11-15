using System.Net.Http.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;
using RuntimeApps.Authentication.Service;

namespace RuntimeApps.Authentication.Controller {
    public static class RefreshTokenApiEndpointRouteBuilderExtensions {
        /// <summary>
        /// Maps refresh, current-session logout, and logout-all endpoints. This is called automatically
        /// by MapLoginApi when AddRefreshToken has registered the refresh-token service.
        /// </summary>
        public static IEndpointRouteBuilder MapRefreshTokenApi<TUser, TKey>(this IEndpointRouteBuilder endpoints)
            where TUser : IdentityUser<TKey>
            where TKey : IEquatable<TKey> {
            var routes = endpoints.MapGroup("");

            routes.MapPost("refresh", async Task<IResult> (HttpContext context,
                IUserManager<TUser> userManager,
                ISignInManager<TUser> signInManager,
                IRefreshTokenService<TKey> refreshTokenService,
                IRefreshTokenRequestLimiter requestLimiter,
                IServiceProvider services,
                IUserClaimsPrincipalFactory<TUser> claimsFactory,
                IAuthenticationSchemeProvider schemeProvider,
                IAuthenticationHandlerProvider handlerProvider,
                IOptions<RefreshTokenOptions> options) => {
                if(!await requestLimiter.IsAllowedAsync(context, context.RequestAborted))
                    return Results.StatusCode(StatusCodes.Status429TooManyRequests);

                var isCookie = await HasCookieSignInHandlerAsync(context, schemeProvider, handlerProvider);
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

                var user = await userManager.FindByIdAsync(Convert.ToString(session.UserId));
                if(user == null ||
                   await userManager.IsLockedOutAsync(user) ||
                   !await signInManager.CanSignInAsync(user)) {
                    await refreshTokenService.RevokeAsync(session.RefreshToken, context.RequestAborted);
                    return Results.Unauthorized();
                }

                try {
                    if(isCookie) {
                        var principal = await claimsFactory.CreateAsync(user);
                        await context.SignInAsync(principal);
                        AppendRefreshCookie(context, options.Value, session.RefreshToken, session.ExpiresAt);
                        return Results.NoContent();
                    }

                    var jwtProvider = services.GetService<IJwtProvider<TUser>>();
                    if(jwtProvider == null) {
                        await refreshTokenService.RevokeAsync(session.RefreshToken, CancellationToken.None);
                        return Results.Problem("JWT authentication is not configured.", statusCode: StatusCodes.Status500InternalServerError);
                    }

                    var accessToken = await jwtProvider.GenerateTokenAsync(user);
                    accessToken.RefreshToken = session.RefreshToken;
                    accessToken.RefreshTokenExpireDate = session.ExpiresAt;
                    accessToken.SessionId = session.SessionId;
                    return Results.Ok(accessToken);
                }
                catch {
                    await refreshTokenService.RevokeAsync(session.RefreshToken, CancellationToken.None);
                    throw;
                }
            });

            routes.MapPost("logout", async Task<IResult> (HttpContext context,
                IRefreshTokenService<TKey> refreshTokenService,
                IOptions<RefreshTokenOptions> options) => {
                var isCookie = await HasCookieSignInHandlerAsync(context,
                    context.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>(),
                    context.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>());
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
                    await context.SignOutAsync();
                context.Response.Cookies.Delete(options.Value.CookieName, new CookieOptions {
                    Path = options.Value.CookiePath,
                    Secure = options.Value.CookieSecure,
                    HttpOnly = true,
                    SameSite = options.Value.CookieSameSite
                });
                return Results.NoContent();
            });

            routes.MapPost("logout/all", async Task<IResult> (HttpContext context,
                IUserManager<TUser> userManager,
                IRefreshTokenService<TKey> refreshTokenService,
                IOptions<RefreshTokenOptions> options) => {
                var user = await userManager.GetUserAsync(context.User);
                if(user == null)
                    return Results.Unauthorized();

                var isCookie = await HasCookieSignInHandlerAsync(context,
                    context.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>(),
                    context.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>());
                if(isCookie && !IsAllowedOrigin(context, options.Value))
                    return Results.StatusCode(StatusCodes.Status403Forbidden);

                await refreshTokenService.RevokeAllAsync(user.Id, context.RequestAborted);
                if(isCookie)
                    await context.SignOutAsync();
                context.Response.Cookies.Delete(options.Value.CookieName, new CookieOptions {
                    Path = options.Value.CookiePath,
                    Secure = options.Value.CookieSecure,
                    HttpOnly = true,
                    SameSite = options.Value.CookieSameSite
                });
                return Results.NoContent();
            }).RequireAuthorization();

            return endpoints;
        }

        private static async Task<bool> HasCookieSignInHandlerAsync(
            HttpContext context,
            IAuthenticationSchemeProvider schemeProvider,
            IAuthenticationHandlerProvider handlerProvider) {
            var scheme = await schemeProvider.GetDefaultSignInSchemeAsync();
            if(scheme == null)
                return false;

            var handler = await handlerProvider.GetHandlerAsync(context, scheme.Name);
            return handler is IAuthenticationSignInHandler;
        }

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