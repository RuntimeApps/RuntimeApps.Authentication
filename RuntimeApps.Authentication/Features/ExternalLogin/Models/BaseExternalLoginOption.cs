namespace RuntimeApps.Authentication.Features.ExternalLogin.Models {
    public class BaseExternalLoginOption {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        /// <summary>
        /// Decides whether the default email trust policy accepts this provider's email claim.
        /// Each provider option class sets its own default.
        /// </summary>
        public ExternalLoginEmailTrustMode EmailTrust { get; set; } = ExternalLoginEmailTrustMode.Verified;
    }
}
