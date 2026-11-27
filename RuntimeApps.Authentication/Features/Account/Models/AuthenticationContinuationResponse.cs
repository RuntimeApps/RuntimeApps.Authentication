using System.Text.Json.Serialization;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Features.Account.Models {
    /// <summary>
    /// Indicates that the first login step succeeded and another authentication step is required. It never
    /// contains an access or refresh token. When two-factor login is enabled it also carries the challenge to answer.
    /// </summary>
    public sealed record AuthenticationContinuationResponse(bool RequiresTwoFactor = true) {
        /// <summary>Opaque handle to send back with the code. Absent when two-factor login is not enabled.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string TwoFactorChallenge { get; init; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public DateTimeOffset? ExpiresAt { get; init; }

        /// <summary>Methods the user can use. An empty list means no method is enrolled.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public IReadOnlyList<TwoFactorMethodInfo> Methods { get; init; }
    }
}
