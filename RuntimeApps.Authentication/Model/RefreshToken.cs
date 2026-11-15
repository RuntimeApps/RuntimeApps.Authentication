namespace RuntimeApps.Authentication.Model {
    /// <summary>
    /// Persisted refresh-token record. The raw token is never stored; only its SHA-256 hash is persisted.
    /// </summary>
    public class RefreshToken<TKey>
        where TKey : IEquatable<TKey> {
        public Guid Id { get; set; }
        public TKey UserId { get; set; }
        /// <summary>Identifies one authenticated client session. All rotations in a session share this value.</summary>
        public Guid FamilyId { get; set; }
        public string TokenHash { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }
        public DateTimeOffset? RevokedAt { get; set; }
        public Guid? ReplacedByTokenId { get; set; }
        public string SessionName { get; set; }
    }
}