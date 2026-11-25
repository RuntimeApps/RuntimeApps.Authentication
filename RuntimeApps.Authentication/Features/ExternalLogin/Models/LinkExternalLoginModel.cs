using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.ExternalLogin.Models {
    /// <summary>
    /// Request to link an external identity to the signed-in account. Linking requires fresh proof of
    /// control of the account: the current password, or a fresh token from a provider that is already
    /// linked to the account.
    /// </summary>
    public class LinkExternalLoginModel {
        [Required]
        public string Provider { get; set; }
        [Required]
        public string Token { get; set; }
        /// <summary>Current password of the account. Accepted as re-authentication when the account has a password.</summary>
        public string CurrentPassword { get; set; }
        /// <summary>Provider of an already-linked identity used for re-authentication.</summary>
        public string ReauthenticationProvider { get; set; }
        /// <summary>Fresh token from <see cref="ReauthenticationProvider"/>.</summary>
        public string ReauthenticationToken { get; set; }
    }
}
