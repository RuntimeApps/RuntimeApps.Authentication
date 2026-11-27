using System.Text.Json.Serialization;

namespace RuntimeApps.Authentication.Shared.Models {
    public class Token {
        public string AuthenticationToken { get; set; }
        public DateTimeOffset? ExpireDate { get; set; }
        /// <summary>Opaque refresh credential. Returned only when refresh-token support is enabled in JWT mode.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string RefreshToken { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public DateTimeOffset? RefreshTokenExpireDate { get; set; }
        /// <summary>Identifies the authenticated session, not a secret.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Guid? SessionId { get; set; }
        /// <summary>True when external authentication succeeded but email verification is still required.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public bool VerificationRequired { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string VerificationHandle { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public DateTimeOffset? VerificationExpiresAt { get; set; }
        /// <summary>
        /// Opaque handle of a pending second-factor challenge. Set only on the metadata of a login that still needs
        /// a second step; such a result carries no access or refresh token.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string TwoFactorChallenge { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public DateTimeOffset? TwoFactorExpiresAt { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public IReadOnlyList<TwoFactorMethodInfo> TwoFactorMethods { get; set; }
    }
}
