using RuntimeApps.Authentication.Features.RefreshTokens.Models;
namespace RuntimeApps.Authentication.Features.RefreshTokens.Contracts {
    /// <summary>
    /// Persistence contract for refresh tokens. Implementations must make TryRotateAsync atomic:
    /// the old token must be consumed and its replacement persisted as one operation. Implementations must assign the token's Id during CreateAsync and TryRotateAsync before returning successfully.
    /// </summary>
    public interface IRefreshTokenStore<TKey>
        where TKey : IEquatable<TKey> {
        Task CreateAsync(RefreshToken<TKey> token, CancellationToken cancellationToken = default);
        Task<RefreshToken<TKey>> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);
        Task<bool> TryRotateAsync(
            TKey tokenId,
            string expectedTokenHash,
            RefreshToken<TKey> replacement,
            DateTimeOffset now,
            CancellationToken cancellationToken = default);
        Task RevokeFamilyAsync(Guid familyId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);
        Task<int> RevokeAllAsync(TKey userId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);
    }
}
