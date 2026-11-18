namespace RuntimeApps.Authentication.Model {
    public sealed class VerifyRegistrationModel {
        public string VerificationHandle { get; set; }
        public string Code { get; set; }
    }
}