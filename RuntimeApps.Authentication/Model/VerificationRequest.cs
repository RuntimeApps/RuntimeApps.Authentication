namespace RuntimeApps.Authentication.Model {
    /// <summary>
    /// Persisted state for a verification operation. The raw public handle and verification code
    /// must never be stored in this entity.
    /// </summary>
    public class VerificationRequest<TKey> where TKey : IEquatable<TKey> {
        public TKey Id { get; set; }
        public TKey UserId { get; set; }
        public VerificationPurpose Purpose { get; set; }
        public VerificationChannel Channel { get; set; }
        public string CustomPurpose { get; set; }
        public string CustomChannel { get; set; }
        public string Destination { get; set; }
        public string NormalizedDestination { get; set; }
        public string PublicHandleHash { get; set; }
        public string CodeVerifier { get; set; }
        public int CodeVersion { get; set; }
        public int FailedAttempts { get; set; }
        public int SendCount { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset LastSentAt { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }
        public DateTimeOffset? CompletedAt { get; set; }
        public VerificationRequestStatus Status { get; set; }
    }
}