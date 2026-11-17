using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Interface {
    public interface IRefreshTokenService<TKey>
        where TKey : IEquatable<TKey> {
        Task<RefreshTokenSession<TKey>> CreateSessionAsync(
            TKey userId,
            string sessionName = null,
            CancellationToken cancellationToken = default);
        /// <summary>Returns null for unknown, expired, revoked, or reused credentials.</summary>
        Task<RefreshTokenSession<TKey>> RotateAsync(
            string refreshToken,
            CancellationToken cancellationToken = default);
        Task<bool> RevokeAsync(string refreshToken, CancellationToken cancellationToken = default);
        Task<int> RevokeAllAsync(TKey userId, CancellationToken cancellationToken = default);
    }
}