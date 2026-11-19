namespace RuntimeApps.Authentication.Model {
    public sealed class VerificationCodeContext<TUser, TKey> where TKey : IEquatable<TKey> {
        public TUser User { get; init; }
        public TKey UserId { get; init; }
        public TKey RequestId { get; init; }
        public VerificationPurpose Purpose { get; init; }
        public VerificationChannel Channel { get; init; }
        public string CustomPurpose { get; init; }
        public string CustomChannel { get; init; }
        public string Destination { get; init; }
        /// <summary>Opaque public handle associated with the verification request.</summary>
        public string VerificationHandle { get; init; }
        /// <summary>Configured password-recovery delivery method, only set for password-reset requests.</summary>
        public ForgotPasswordMethod? PasswordResetMethod { get; init; }
        /// <summary>Frontend reset URL containing the handle and token in its URL fragment, for link mode.</summary>
        public string VerificationUrl { get; init; }
    }
}