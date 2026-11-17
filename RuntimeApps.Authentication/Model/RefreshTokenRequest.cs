using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Model {
    /// <summary>
    /// Request body used by JWT clients to refresh or revoke a refresh-token session.
    /// Cookie-authenticated clients send the refresh token in the HttpOnly cookie instead.
    /// </summary>
    public sealed class RefreshTokenRequest {
        /// <summary>The opaque refresh token issued when the session was created or last refreshed.</summary>
        [Required]
        public string RefreshToken { get; set; }
    }
}