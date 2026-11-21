using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Features.Account.Services {
    public sealed class JwtAuthenticationSessionIssuer<TUser, TKey> : IAuthenticationSessionIssuer<TUser>
        where TUser : IdentityUser<TKey> where TKey : IEquatable<TKey> {
        private readonly IJwtProvider<TUser> _jwtProvider;
        private readonly IRefreshTokenService<TKey> _refreshTokens;
        private readonly IHttpContextAccessor _http;
        private readonly RefreshTokenOptions _options;
        public JwtAuthenticationSessionIssuer(IJwtProvider<TUser> jwtProvider, IHttpContextAccessor http,
            IRefreshTokenService<TKey> refreshTokens = null, IOptions<RefreshTokenOptions> options = null) {
            _jwtProvider = jwtProvider; _http = http; _refreshTokens = refreshTokens; _options = options?.Value ?? new();
        }
        public async Task<Token> IssueAsync(TUser user, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            var token = await _jwtProvider.GenerateTokenAsync(user);
            if(_refreshTokens != null) {
                var session = await _refreshTokens.CreateSessionAsync(user.Id, cancellationToken: cancellationToken);
                token.RefreshToken = session.RefreshToken; token.RefreshTokenExpireDate = session.ExpiresAt; token.SessionId = session.SessionId;
            }
            return token;
        }
    }
}
