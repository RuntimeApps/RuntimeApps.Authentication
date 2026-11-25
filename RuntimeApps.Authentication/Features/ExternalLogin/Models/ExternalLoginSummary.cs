namespace RuntimeApps.Authentication.Features.ExternalLogin.Models {
    /// <summary>A linked external login as shown to the account owner. Provider subject keys are never exposed.</summary>
    public class ExternalLoginSummary {
        public string Provider { get; set; }
    }
}
