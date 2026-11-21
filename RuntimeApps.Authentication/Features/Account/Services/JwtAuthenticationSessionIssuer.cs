using Microsoft.AspNetCore.Identity;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Features.Account.Services {
    public sealed class JwtAuthenticationSessionIssuer<TUser, TKey> : IAuthenticationSessionIssuer<TUser>
        where TUser : IdentityUser<TKey> where TKey : IEquatable<TKey> {
        private readonly IJwtProvider<TUser> _jwtProvider;
        private readonly IRefreshTokenService<TKey> _refreshTokens;
        public JwtAuthenticationSessionIssuer(IJwtProvider<TUser> jwtProvider, IRefreshTokenService<TKey> refreshTokens = null) {
            _jwtProvider = jwtProvider; _refreshTokens = refreshTokens;
        }
        public async Task<Token> IssueAsync(TUser user, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            var token = await _jwtProvider.GenerateTokenAsync(user, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            if(_refreshTokens != null) {
                var session = await _refreshTokens.CreateSessionAsync(user.Id, cancellationToken: cancellationToken);
                token.RefreshToken = session.RefreshToken; token.RefreshTokenExpireDate = session.ExpiresAt; token.SessionId = session.SessionId;
            }
            return token;
        }
    }
}
