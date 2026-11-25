using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.PasswordRecovery.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.Registration.Contracts;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
using RuntimeApps.Authentication.Features.PasswordRecovery.Models;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Features.Registration.Models;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Identity.Models;
using RuntimeApps.Authentication.Shared.Models;
using RuntimeApps.Authentication.Features.Account.Services;
using RuntimeApps.Authentication.Features.ExternalLogin.Providers;
using RuntimeApps.Authentication.Features.ExternalLogin.Services;
using RuntimeApps.Authentication.Features.PasswordRecovery.Services;
using RuntimeApps.Authentication.Features.RefreshTokens.Services;
using RuntimeApps.Authentication.Features.Registration.Services;
using RuntimeApps.Authentication.Features.Verification.Services;
using RuntimeApps.Authentication.Identity;
namespace RuntimeApps.Authentication.Test {
    public class RefreshTokenServiceTest {
        private readonly InMemoryRefreshTokenStore<string> _store = new();
        private readonly MutableTimeProvider _time = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        private IRefreshTokenService<string> CreateService(bool revokeFamilyOnReuse = true, int absoluteDays = 90) =>
            new RefreshTokenService<string>(_store, Options.Create(new RefreshTokenOptions {
                TokenLifetime = TimeSpan.FromDays(30),
                AbsoluteSessionLifetime = TimeSpan.FromDays(absoluteDays),
                RevokeFamilyOnReuse = revokeFamilyOnReuse
            }), _time);

        [Fact]
        public async Task CreateSession_CreatesIndependentSessionForEachLogin() {
            var service = CreateService();
            var cancellationToken = TestContext.Current.CancellationToken;

            var first = await service.CreateSessionAsync("user-1", cancellationToken: cancellationToken);
            var second = await service.CreateSessionAsync("user-1", cancellationToken: cancellationToken);

            Assert.NotEqual(first.SessionId, second.SessionId);
            Assert.NotEqual(first.RefreshToken, second.RefreshToken);
            Assert.Equal(2, _store.Tokens.Count);
            Assert.All(_store.Tokens, token => Assert.NotEqual(token.TokenHash, first.RefreshToken));
        }

        [Fact]
        public async Task RotateAsync_CreatesReplacementInSameFamily() {
            var service = CreateService();
            var cancellationToken = TestContext.Current.CancellationToken;
            var first = await service.CreateSessionAsync("user-1", cancellationToken: cancellationToken);

            var second = await service.RotateAsync(first.RefreshToken, cancellationToken);

            Assert.NotNull(second);
            Assert.Equal(first.SessionId, second.SessionId);
            Assert.NotEqual(first.RefreshToken, second.RefreshToken);
            Assert.Equal(2, _store.Tokens.Count);
            Assert.Contains(_store.Tokens, token => token.HasReplacement);
        }

        [Fact]
        public async Task RotateAsync_ReusedTokenRevokesOnlyItsFamily() {
            var service = CreateService();
            var cancellationToken = TestContext.Current.CancellationToken;
            var firstSession = await service.CreateSessionAsync("user-1", cancellationToken: cancellationToken);
            var otherSession = await service.CreateSessionAsync("user-1", cancellationToken: cancellationToken);
            var replacement = await service.RotateAsync(firstSession.RefreshToken, cancellationToken);

            var replay = await service.RotateAsync(firstSession.RefreshToken, cancellationToken);
            var otherStillWorks = await service.RotateAsync(otherSession.RefreshToken, cancellationToken);

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
            var cancellationToken = TestContext.Current.CancellationToken;
            var userOneSession = await service.CreateSessionAsync("user-1", cancellationToken: cancellationToken);
            var userTwoSession = await service.CreateSessionAsync("user-2", cancellationToken: cancellationToken);

            var count = await service.RevokeAllAsync("user-1", cancellationToken);

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
            var cancellationToken = TestContext.Current.CancellationToken;
            var session = await service.CreateSessionAsync("user-1", cancellationToken: cancellationToken);

            var results = await Task.WhenAll(
                service.RotateAsync(session.RefreshToken, cancellationToken),
                service.RotateAsync(session.RefreshToken, cancellationToken));

            Assert.Single(results, result => result != null);
            Assert.All(_store.Tokens.Where(token => token.FamilyId == session.SessionId),
                token => Assert.NotNull(token.RevokedAt));
        }

        [Fact]
        public async Task RotateAsync_RejectsExpiredToken() {
            var service = CreateService();
            var cancellationToken = TestContext.Current.CancellationToken;
            var session = await service.CreateSessionAsync("user-1", cancellationToken: cancellationToken);
            _time.Advance(TimeSpan.FromDays(31));

            Assert.Null(await service.RotateAsync(session.RefreshToken, cancellationToken));
        }

        [Fact]
        public async Task CreateSession_SetsAbsoluteExpiryAndCapsTokenExpiryByIt() {
            var cancellationToken = TestContext.Current.CancellationToken;
            var start = _time.GetUtcNow();

            var normal = await CreateService().CreateSessionAsync("user-1", cancellationToken: cancellationToken);
            var shortSession = await CreateService(absoluteDays: 30).CreateSessionAsync("user-2", cancellationToken: cancellationToken);

            Assert.Equal(start.AddDays(30), normal.ExpiresAt);
            Assert.Equal(start.AddDays(90), _store.Tokens.Single(token => token.FamilyId == normal.SessionId).AbsoluteExpiresAt);
            Assert.Equal(start.AddDays(30), shortSession.ExpiresAt);
            Assert.Equal(start.AddDays(30), _store.Tokens.Single(token => token.FamilyId == shortSession.SessionId).AbsoluteExpiresAt);
        }

        [Fact]
        public async Task RotateAsync_ReplacementKeepsOriginalAbsoluteExpiry() {
            var service = CreateService();
            var cancellationToken = TestContext.Current.CancellationToken;
            var start = _time.GetUtcNow();
            var first = await service.CreateSessionAsync("user-1", cancellationToken: cancellationToken);
            _time.Advance(TimeSpan.FromDays(10));

            var second = await service.RotateAsync(first.RefreshToken, cancellationToken);

            Assert.NotNull(second);
            Assert.Equal(start.AddDays(40), second.ExpiresAt);
            Assert.All(_store.Tokens, token => Assert.Equal(start.AddDays(90), token.AbsoluteExpiresAt));
        }

        [Fact]
        public async Task RotateAsync_RepeatedRotationCannotExtendSessionBeyondAbsoluteExpiry() {
            var service = CreateService();
            var cancellationToken = TestContext.Current.CancellationToken;
            var start = _time.GetUtcNow();
            var absolute = start.AddDays(90);
            var session = await service.CreateSessionAsync("user-1", cancellationToken: cancellationToken);

            // Rotate every 20 days: days 20, 40, 60 and 80. The day-80 replacement would reach day 110 without a cap.
            RefreshTokenSession<string> latest = session;
            for(var day = 20; day <= 80; day += 20) {
                _time.Advance(TimeSpan.FromDays(20));
                latest = await service.RotateAsync(latest.RefreshToken, cancellationToken);
                Assert.NotNull(latest);
                Assert.True(latest.ExpiresAt <= absolute);
            }

            Assert.Equal(absolute, latest.ExpiresAt);
            Assert.Equal(session.SessionId, latest.SessionId);

            _time.Advance(TimeSpan.FromDays(11));
            Assert.Null(await service.RotateAsync(latest.RefreshToken, cancellationToken));
        }

        [Fact]
        public async Task RotateAsync_RejectsTokenPastAbsoluteExpiryEvenWhenTokenExpiryIsStillInTheFuture() {
            var service = CreateService();
            var cancellationToken = TestContext.Current.CancellationToken;
            var now = _time.GetUtcNow();
            const string rawToken = "crafted-refresh-token";
            await _store.CreateAsync(new RefreshToken<string> {
                Id = default!,
                UserId = "user-1",
                FamilyId = Guid.NewGuid(),
                TokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken))),
                CreatedAt = now.AddDays(-100),
                ExpiresAt = now.AddDays(10),
                AbsoluteExpiresAt = now.AddMinutes(-1)
            }, cancellationToken);

            Assert.Null(await service.RotateAsync(rawToken, cancellationToken));
            Assert.Single(_store.Tokens);
        }

        [Fact]
        public async Task RotateAsync_RejectsRecordWithoutAbsoluteExpiry() {
            var service = CreateService();
            var cancellationToken = TestContext.Current.CancellationToken;
            var now = _time.GetUtcNow();
            const string rawToken = "record-without-absolute-expiry";
            await _store.CreateAsync(new RefreshToken<string> {
                Id = default!,
                UserId = "user-1",
                FamilyId = Guid.NewGuid(),
                TokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken))),
                CreatedAt = now,
                ExpiresAt = now.AddDays(10)
            }, cancellationToken);

            Assert.Null(await service.RotateAsync(rawToken, cancellationToken));
        }

        [Fact]
        public async Task RotateAsync_ConcurrentRotationNearAbsoluteExpiryStaysCapped() {
            var service = CreateService();
            var cancellationToken = TestContext.Current.CancellationToken;
            var absolute = _time.GetUtcNow().AddDays(90);
            RefreshTokenSession<string> session = await service.CreateSessionAsync("user-1", cancellationToken: cancellationToken);

            // A single token only lives 30 days, so keep the session alive by rotating at days 25, 50 and 75.
            // The day-75 replacement is already capped at the absolute expiry (day 90).
            for(var i = 0; i < 3; i++) {
                _time.Advance(TimeSpan.FromDays(25));
                session = await service.RotateAsync(session.RefreshToken, cancellationToken);
                Assert.NotNull(session);
            }
            Assert.Equal(absolute, session.ExpiresAt);

            // Day 85: the live token is still valid and a fresh 30-day window would reach day 115.
            _time.Advance(TimeSpan.FromDays(10));
            var results = await Task.WhenAll(
                service.RotateAsync(session.RefreshToken, cancellationToken),
                service.RotateAsync(session.RefreshToken, cancellationToken));

            var winner = Assert.Single(results, result => result != null);
            Assert.Equal(absolute, winner.ExpiresAt);
            Assert.All(_store.Tokens, token => Assert.True(token.ExpiresAt <= token.AbsoluteExpiresAt));
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
                lock(_sync) {
                    if(EqualityComparer<T>.Default.Equals(token.Id, default!))
                        token.Id = (T)Convert.ChangeType(Guid.NewGuid().ToString("N"), typeof(T));
                    _tokens.Add(Clone(token));
                }
                return Task.CompletedTask;
            }

            public Task<RefreshToken<T>> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) {
                lock(_sync) return Task.FromResult(_tokens.Where(token => token.TokenHash == tokenHash).Select(Clone).SingleOrDefault());
            }

            public Task<bool> TryRotateAsync(T tokenId, string expectedTokenHash, RefreshToken<T> replacement,
                DateTimeOffset now, CancellationToken cancellationToken = default) {
                lock(_sync) {
                    var current = _tokens.SingleOrDefault(token => EqualityComparer<T>.Default.Equals(token.Id, tokenId) &&
                        token.TokenHash == expectedTokenHash && token.RevokedAt == null && token.ExpiresAt > now);
                    if(current == null)
                        return Task.FromResult(false);
                    current.RevokedAt = now;
                    if(EqualityComparer<T>.Default.Equals(replacement.Id, default!))
                        replacement.Id = (T)Convert.ChangeType(Guid.NewGuid().ToString("N"), typeof(T));
                    current.ReplacedByTokenId = replacement.Id;
                    current.HasReplacement = true;
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
                AbsoluteExpiresAt = token.AbsoluteExpiresAt,
                RevokedAt = token.RevokedAt,
                ReplacedByTokenId = token.ReplacedByTokenId,
                HasReplacement = token.HasReplacement,
                SessionName = token.SessionName
            };
        }
    }
}