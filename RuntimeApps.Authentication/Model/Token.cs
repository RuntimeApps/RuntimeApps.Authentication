namespace RuntimeApps.Authentication.Model {
    public class Token {
        public string AuthenticationToken { get; set; }
        public DateTimeOffset? ExpireDate { get; set; }
        /// <summary>Opaque refresh credential. Returned only when refresh-token support is enabled in JWT mode.</summary>
        public string RefreshToken { get; set; }
        public DateTimeOffset? RefreshTokenExpireDate { get; set; }
        /// <summary>Identifies the authenticated session, not a secret.</summary>
        public Guid? SessionId { get; set; }
    }
}