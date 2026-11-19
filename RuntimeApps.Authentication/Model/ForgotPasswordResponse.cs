namespace RuntimeApps.Authentication.Model {
    /// <summary>
    /// Generic response for a password-reset request. Unknown or ineligible accounts receive
    /// a random non-existent handle so the response shape does not disclose account existence.
    /// </summary>
    public sealed class ForgotPasswordResponse {
        public string Message { get; init; } = "If an eligible account exists for this email address, recovery instructions will be sent.";
        public string VerificationHandle { get; init; }
    }
}