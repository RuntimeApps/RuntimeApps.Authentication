namespace RuntimeApps.Authentication.Features.Registration.Models {
    public sealed class VerifyRegistrationModel {
        public string VerificationHandle { get; set; }
        public string Code { get; set; }
    }
}
