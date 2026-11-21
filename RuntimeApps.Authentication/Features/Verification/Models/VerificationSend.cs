namespace RuntimeApps.Authentication.Features.Verification.Models {
    /// <summary>Immutable audit/rate-limit record for one attempted verification delivery.</summary>
    public sealed class VerificationSend {
        public long Id { get; set; }
        public string NormalizedDestination { get; set; }
        public VerificationPurpose Purpose { get; set; }
        public VerificationChannel Channel { get; set; }
        public DateTimeOffset SentAt { get; set; }
    }
}
