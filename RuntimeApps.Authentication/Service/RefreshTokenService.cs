using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Service {
    public sealed class RefreshTokenService<TKey> : IRefreshTokenService<TKey>
        where TKey : IEquatable<TKey> {
        private readonly IRefreshTokenStore<TKey> _store;
        private readonly RefreshTokenOptions _options;
        private readonly TimeProvider _timeProvider;

        public RefreshTokenService(
            IRefreshTokenStore<TKey> store,
            IOptions<RefreshTokenOptions> options,
            TimeProvider timeProvider) {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
            _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        }

        public async Task<RefreshTokenSession<TKey>> CreateSessionAsync(
            TKey userId,
            string sessionName = null,
            CancellationToken cancellationToken = default) {
            ArgumentNullException.ThrowIfNull(userId);
            ValidateSessionName(sessionName);

            var now = _timeProvider.GetUtcNow();
            var rawToken = GenerateToken();
            var record = new RefreshToken<TKey> {
                Id = Guid.NewGuid(),
                UserId = userId,
                FamilyId = Guid.NewGuid(),
                TokenHash = HashToken(rawToken),
                CreatedAt = now,
                ExpiresAt = now.Add(_options.TokenLifetime),
                SessionName = sessionName
            };

            await _store.CreateAsync(record, cancellationToken);
            return ToSession(record, rawToken);
        }

        public async Task<RefreshTokenSession<TKey>> RotateAsync(
            string refreshToken,
            CancellationToken cancellationToken = default) {
            if(string.IsNullOrWhiteSpace(refreshToken))
                return null;

            var tokenHash = HashToken(refreshToken);
            var current = await _store.FindByHashAsync(tokenHash, cancellationToken);
            if(current == null)
                return null;

            var now = _timeProvider.GetUtcNow();
            if(current.RevokedAt.HasValue) {
                if(current.ReplacedByTokenId.HasValue && _options.RevokeFamilyOnReuse)
                    await _store.RevokeFamilyAsync(current.FamilyId, now, cancellationToken);
                return null;
            }

            if(current.ExpiresAt <= now)
                return null;

            var rawReplacement = GenerateToken();
            var replacement = new RefreshToken<TKey> {
                Id = Guid.NewGuid(),
                UserId = current.UserId,
                FamilyId = current.FamilyId,
                TokenHash = HashToken(rawReplacement),
                CreatedAt = now,
                ExpiresAt = now.Add(_options.TokenLifetime),
                SessionName = current.SessionName
            };

            var rotated = await _store.TryRotateAsync(
                current.Id, tokenHash, replacement, now, cancellationToken);

            if(!rotated) {
                // Distinguish a concurrent replay from an expiry race. Only a token that another
                // request actually consumed and replaced should trigger family-wide revocation.
                var latest = await _store.FindByHashAsync(tokenHash, cancellationToken);
                if(latest?.RevokedAt.HasValue == true &&
                   latest.ReplacedByTokenId.HasValue &&
                   _options.RevokeFamilyOnReuse) {
                    await _store.RevokeFamilyAsync(latest.FamilyId, now, cancellationToken);
                }
                return null;
            }

            return ToSession(replacement, rawReplacement);
        }

        public async Task<bool> RevokeAsync(
            string refreshToken,
            CancellationToken cancellationToken = default) {
            if(string.IsNullOrWhiteSpace(refreshToken))
                return false;

            var current = await _store.FindByHashAsync(HashToken(refreshToken), cancellationToken);
            if(current == null)
                return false;

            await _store.RevokeFamilyAsync(current.FamilyId, _timeProvider.GetUtcNow(), cancellationToken);
            return true;
        }

        public Task<int> RevokeAllAsync(TKey userId, CancellationToken cancellationToken = default) {
            ArgumentNullException.ThrowIfNull(userId);
            return _store.RevokeAllAsync(userId, _timeProvider.GetUtcNow(), cancellationToken);
        }

        private RefreshTokenSession<TKey> ToSession(RefreshToken<TKey> token, string rawToken) => new() {
            UserId = token.UserId,
            SessionId = token.FamilyId,
            RefreshToken = rawToken,
            ExpiresAt = token.ExpiresAt
        };

        private static string GenerateToken() {
            var bytes = RandomNumberGenerator.GetBytes(32);
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private static string HashToken(string token) {
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
            return Convert.ToHexString(hash);
        }

        private static void ValidateSessionName(string sessionName) {
            if(sessionName?.Length > 100)
                throw new ArgumentException("Session name cannot exceed 100 characters.", nameof(sessionName));
        }
    }
}