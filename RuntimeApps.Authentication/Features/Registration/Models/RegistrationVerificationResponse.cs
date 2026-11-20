namespace RuntimeApps.Authentication.Features.Registration.Models {
    public sealed class RegistrationVerificationResponse {
        /// <summary>
        /// A generic client-facing message returned for registration and resend requests.
        /// It deliberately does not disclose whether an account exists or whether a message was sent.
        /// </summary>
        public string Message { get; init; } = "If this email address can be registered, check your inbox for a verification message.";
        public string VerificationHandle { get; init; }
        public DateTimeOffset ExpiresAt { get; init; }
    }
}
