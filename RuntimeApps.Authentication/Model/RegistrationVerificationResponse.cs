namespace RuntimeApps.Authentication.Model {
    public sealed class RegistrationVerificationResponse {
        public string Message { get; init; } = "If the account can be registered, a verification message will be sent.";
        public string VerificationHandle { get; init; }
        public DateTimeOffset ExpiresAt { get; init; }
    }
}