namespace RuntimeApps.Authentication.Features.RefreshTokens.Models {
    /// <summary>
    /// Persisted refresh-token record. The raw token is never stored; only its SHA-256 hash is persisted.
    /// </summary>
    public class RefreshToken<TKey>
        where TKey : IEquatable<TKey> {
        /// <summary>Primary key using the same type as the associated user identifier.</summary>
        public TKey Id { get; set; }
        public TKey UserId { get; set; }
        /// <summary>Identifies one authenticated client session. All rotations in a session share this value.</summary>
        public Guid FamilyId { get; set; }
        public string TokenHash { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }
        /// <summary>
        /// End of the whole session. It is fixed when the session is created and copied unchanged to every
        /// rotated replacement, so repeated rotation cannot extend it. ExpiresAt never exceeds this value.
        /// A record without a value (the default) is treated as already expired.
        /// </summary>
        public DateTimeOffset AbsoluteExpiresAt { get; set; }
        public DateTimeOffset? RevokedAt { get; set; }
        /// <summary>Identifier of the replacement token, using the same key type as Id and UserId.</summary>
        public TKey ReplacedByTokenId { get; set; }
        /// <summary>Indicates whether this token was rotated and ReplacedByTokenId is populated.</summary>
        public bool HasReplacement { get; set; }
        public string SessionName { get; set; }
    }
}
