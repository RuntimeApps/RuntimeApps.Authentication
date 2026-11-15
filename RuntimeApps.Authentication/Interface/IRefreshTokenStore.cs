using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Interface {
    /// <summary>
    /// Persistence contract for refresh tokens. Implementations must make TryRotateAsync atomic:
    /// the old token must be consumed and its replacement persisted as one operation.
    /// </summary>
    public interface IRefreshTokenStore<TKey>
        where TKey : IEquatable<TKey> {
        Task CreateAsync(RefreshToken<TKey> token, CancellationToken cancellationToken = default);
        Task<RefreshToken<TKey>> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);
        Task<bool> TryRotateAsync(
            Guid tokenId,
            string expectedTokenHash,
            RefreshToken<TKey> replacement,
            DateTimeOffset now,
            CancellationToken cancellationToken = default);
        Task RevokeFamilyAsync(Guid familyId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);
        Task<int> RevokeAllAsync(TKey userId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);
    }
}