using System.Text.Json.Serialization;

namespace RuntimeApps.Authentication.Features.PasswordRecovery.Models {
    /// <summary>
    /// Generic response for a password-reset request. In code mode it includes an opaque
    /// verification handle; in link mode the handle is delivered inside the email link.
    /// </summary>
    public sealed class ForgotPasswordResponse {
        public string Message { get; init; } = "If an eligible account exists for this email address, recovery instructions will be sent.";

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string VerificationHandle { get; init; }
    }
}
