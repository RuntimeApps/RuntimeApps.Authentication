using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Features.Account.Services {
    public sealed class CookieAuthenticationSessionIssuer<TUser, TKey> : IAuthenticationSessionIssuer<TUser>
        where TUser : IdentityUser<TKey> where TKey : IEquatable<TKey> {
        private readonly IUserClaimsPrincipalFactory<TUser> _principalFactory; private readonly IHttpContextAccessor _http;
        private readonly CookieSessionOptions _cookie; private readonly IRefreshTokenService<TKey> _refresh;
        private readonly RefreshTokenOptions _refreshOptions;
        public CookieAuthenticationSessionIssuer(IUserClaimsPrincipalFactory<TUser> principalFactory, IHttpContextAccessor http,
            IOptions<CookieSessionOptions> cookie, IRefreshTokenService<TKey> refresh = null, IOptions<RefreshTokenOptions> refreshOptions = null) {
            _principalFactory=principalFactory; _http=http; _cookie=cookie.Value; _refresh=refresh; _refreshOptions=refreshOptions?.Value ?? new();
        }
        public async Task<Token> IssueAsync(TUser user, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            var context = _http.HttpContext ?? throw new InvalidOperationException("An HTTP context is required to issue a cookie session.");
            var principal = await _principalFactory.CreateAsync(user);
            await context.SignInAsync(_cookie.Scheme, principal, new AuthenticationProperties { IsPersistent = _cookie.IsPersistent });
            if(_refresh == null) return null;
            var old=context.Request.Cookies[_refreshOptions.CookieName];
            if(!string.IsNullOrEmpty(old)) await _refresh.RevokeAsync(old, cancellationToken);
            var session=await _refresh.CreateSessionAsync(user.Id, cancellationToken:cancellationToken);
            context.Response.Cookies.Append(_refreshOptions.CookieName, session.RefreshToken, new CookieOptions { HttpOnly=true, Secure=_refreshOptions.CookieSecure, SameSite=_refreshOptions.CookieSameSite, Path=_refreshOptions.CookiePath, Expires=session.ExpiresAt });
            return null;
        }
    }
}
