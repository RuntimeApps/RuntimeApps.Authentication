namespace RuntimeApps.Authentication.Model {
    public sealed class VerificationOptions {
        public const string SectionName = "Authentication:Verification";

        public int CodeLength { get; set; } = 6;
        public TimeSpan CodeLifetime { get; set; } = TimeSpan.FromMinutes(10);
        public int MaximumFailedAttempts { get; set; } = 5;
        public TimeSpan ResendCooldown { get; set; } = TimeSpan.FromSeconds(60);
        public int MaximumSendsPerHour { get; set; } = 5;

        /// <summary>
        /// When true, external identities must complete the configured email verification workflow
        /// before the library issues an application authentication token. Defaults to false.
        /// </summary>
        public bool RequireEmailVerificationForExternalLogins { get; set; }

        public void Validate() {
            if(CodeLength is < 4 or > 12)
                throw new InvalidOperationException("Verification code length must be between 4 and 12.");
            if(CodeLifetime <= TimeSpan.Zero)
                throw new InvalidOperationException("Verification code lifetime must be positive.");
            if(MaximumFailedAttempts < 1)
                throw new InvalidOperationException("Maximum failed attempts must be at least one.");
            if(ResendCooldown < TimeSpan.Zero)
                throw new InvalidOperationException("Resend cooldown cannot be negative.");
            if(MaximumSendsPerHour < 1)
                throw new InvalidOperationException("Maximum sends per hour must be at least one.");
        }
    }
}