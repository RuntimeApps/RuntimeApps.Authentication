using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;
using RuntimeApps.Authentication.Service;

namespace RuntimeApps.Authentication.Test {
    public class RefreshTokenServiceTest {
        private readonly InMemoryRefreshTokenStore<string> _store = new();
        private readonly MutableTimeProvider _time = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        private IRefreshTokenService<string> CreateService(bool revokeFamilyOnReuse = true) =>
            new RefreshTokenService<string>(_store, Options.Create(new RefreshTokenOptions {
                TokenLifetime = TimeSpan.FromDays(30),
                RevokeFamilyOnReuse = revokeFamilyOnReuse
            }), _time);

        [Fact]
        public async Task CreateSession_CreatesIndependentSessionForEachLogin() {
            var service = CreateService();

            var first = await service.CreateSessionAsync("user-1");
            var second = await service.CreateSessionAsync("user-1");

            Assert.NotEqual(first.SessionId, second.SessionId);
            Assert.NotEqual(first.RefreshToken, second.RefreshToken);
            Assert.Equal(2, _store.Tokens.Count);
            Assert.All(_store.Tokens, token => Assert.NotEqual(token.TokenHash, first.RefreshToken));
        }

        [Fact]
        public async Task RotateAsync_CreatesReplacementInSameFamily() {
            var service = CreateService();
            var first = await service.CreateSessionAsync("user-1");

            var second = await service.RotateAsync(first.RefreshToken);

            Assert.NotNull(second);
            Assert.Equal(first.SessionId, second.SessionId);
            Assert.NotEqual(first.RefreshToken, second.RefreshToken);
            Assert.Equal(2, _store.Tokens.Count);
            Assert.Contains(_store.Tokens, token => token.ReplacedByTokenId != null);
        }

        [Fact]
        public async Task RotateAsync_ReusedTokenRevokesOnlyItsFamily() {
            var service = CreateService();
            var firstSession = await service.CreateSessionAsync("user-1");
            var otherSession = await service.CreateSessionAsync("user-1");
            var replacement = await service.RotateAsync(firstSession.RefreshToken);

            var replay = await service.RotateAsync(firstSession.RefreshToken);
            var otherStillWorks = await service.RotateAsync(otherSession.RefreshToken);

            Assert.Null(replay);
            Assert.NotNull(otherStillWorks);
            Assert.Equal(firstSession.SessionId, replacement.SessionId);
            Assert.Equal(otherSession.SessionId, otherStillWorks.SessionId);
            Assert.All(_store.Tokens.Where(token => token.FamilyId == firstSession.SessionId),
                token => Assert.NotNull(token.RevokedAt));
        }

        [Fact]
        public async Task RevokeAllAsync_RevokesOnlyTheSpecifiedUsersSessions() {
            var service = CreateService();
            var userOneSession = await service.CreateSessionAsync("user-1");
            var userTwoSession = await service.CreateSessionAsync("user-2");

            var count = await service.RevokeAllAsync("user-1");

            Assert.Equal(1, count);
            Assert.All(_store.Tokens.Where(token => token.UserId == "user-1"),
                token => Assert.NotNull(token.RevokedAt));
            Assert.All(_store.Tokens.Where(token => token.UserId == "user-2"),
                token => Assert.Null(token.RevokedAt));
            Assert.NotEqual(userOneSession.SessionId, userTwoSession.SessionId);
        }

        [Fact]
        public async Task RotateAsync_ConcurrentReuseDoesNotLeaveFamilyActive() {
            var service = CreateService();
            var session = await service.CreateSessionAsync("user-1");

            var results = await Task.WhenAll(
                service.RotateAsync(session.RefreshToken),
                service.RotateAsync(session.RefreshToken));

            Assert.Single(results.Where(result => result != null));
            Assert.All(_store.Tokens.Where(token => token.FamilyId == session.SessionId),
                token => Assert.NotNull(token.RevokedAt));
        }

        [Fact]
        public async Task RotateAsync_RejectsExpiredToken() {
            var service = CreateService();
            var session = await service.CreateSessionAsync("user-1");
            _time.Advance(TimeSpan.FromDays(31));

            Assert.Null(await service.RotateAsync(session.RefreshToken));
        }

        private sealed class MutableTimeProvider : TimeProvider {
            private DateTimeOffset _now;
            public MutableTimeProvider(DateTimeOffset now) => _now = now;
            public override DateTimeOffset GetUtcNow() => _now;
            public void Advance(TimeSpan duration) => _now = _now.Add(duration);
        }

        private sealed class InMemoryRefreshTokenStore<T> : IRefreshTokenStore<T>
            where T : IEquatable<T> {
            private readonly object _sync = new();
            private readonly List<RefreshToken<T>> _tokens = new();
            public IReadOnlyList<RefreshToken<T>> Tokens {
                get { lock(_sync) return _tokens.Select(Clone).ToList(); }
            }

            public Task CreateAsync(RefreshToken<T> token, CancellationToken cancellationToken = default) {
                lock(_sync) _tokens.Add(Clone(token));
                return Task.CompletedTask;
            }

            public Task<RefreshToken<T>> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) {
                lock(_sync) return Task.FromResult(_tokens.Where(token => token.TokenHash == tokenHash).Select(Clone).SingleOrDefault());
            }

            public Task<bool> TryRotateAsync(Guid tokenId, string expectedTokenHash, RefreshToken<T> replacement,
                DateTimeOffset now, CancellationToken cancellationToken = default) {
                lock(_sync) {
                    var current = _tokens.SingleOrDefault(token => token.Id == tokenId &&
                        token.TokenHash == expectedTokenHash && token.RevokedAt == null && token.ExpiresAt > now);
                    if(current == null)
                        return Task.FromResult(false);
                    current.RevokedAt = now;
                    current.ReplacedByTokenId = replacement.Id;
                    _tokens.Add(Clone(replacement));
                    return Task.FromResult(true);
                }
            }

            public Task RevokeFamilyAsync(Guid familyId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) {
                lock(_sync)
                    foreach(var token in _tokens.Where(token => token.FamilyId == familyId && token.RevokedAt == null))
                        token.RevokedAt = revokedAt;
                return Task.CompletedTask;
            }

            public Task<int> RevokeAllAsync(T userId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) {
                lock(_sync) {
                    var active = _tokens.Where(token => EqualityComparer<T>.Default.Equals(token.UserId, userId) && token.RevokedAt == null).ToList();
                    foreach(var token in active)
                        token.RevokedAt = revokedAt;
                    return Task.FromResult(active.Count);
                }
            }

            private static RefreshToken<T> Clone(RefreshToken<T> token) => new() {
                Id = token.Id,
                UserId = token.UserId,
                FamilyId = token.FamilyId,
                TokenHash = token.TokenHash,
                CreatedAt = token.CreatedAt,
                ExpiresAt = token.ExpiresAt,
                RevokedAt = token.RevokedAt,
                ReplacedByTokenId = token.ReplacedByTokenId,
                SessionName = token.SessionName
            };
        }
    }
}