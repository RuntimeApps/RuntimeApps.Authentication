namespace RuntimeApps.Authentication.Features.Verification.Models {
    /// <summary>Immutable audit/rate-limit record for one attempted verification delivery.</summary>
    public sealed class VerificationSend {
        public long Id { get; set; }
        public string NormalizedDestination { get; set; }
        public VerificationPurpose Purpose { get; set; }
        public VerificationChannel Channel { get; set; }
        /// <summary>Distinguishes custom purposes so each has its own send limit. Null for built-in purposes.</summary>
        public string CustomPurpose { get; set; }
        /// <summary>Distinguishes custom channels so each has its own send limit. Null for built-in channels.</summary>
        public string CustomChannel { get; set; }
        public DateTimeOffset SentAt { get; set; }
    }
}
