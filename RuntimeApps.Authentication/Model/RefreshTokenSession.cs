namespace RuntimeApps.Authentication.Model {
    /// <summary>
    /// Result of creating or rotating a refresh-token session. Contains the raw token exactly once;
    /// callers must return it securely and must not log or persist it.
    /// </summary>
    public sealed class RefreshTokenSession<TKey>
        where TKey : IEquatable<TKey> {
        public TKey UserId { get; init; }
        public Guid SessionId { get; init; }
        public string RefreshToken { get; init; }
        public DateTimeOffset ExpiresAt { get; init; }
    }
}