namespace RuntimeApps.Authentication.Model {
    public sealed class RegistrationVerificationResponse {
        /// <summary>
        /// A generic client-facing message returned for registration and resend requests.
        /// It deliberately does not disclose whether an account exists or whether a message was sent.
        /// </summary>
        public string Message { get; init; } = "If the account can be registered, a verification message will be sent.";
        public string VerificationHandle { get; init; }
        public DateTimeOffset ExpiresAt { get; init; }
    }
}