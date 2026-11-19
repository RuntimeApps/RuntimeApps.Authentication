namespace RuntimeApps.Authentication.Model {
    /// <summary>Identifies the channel used to deliver or complete a verification request.</summary>
    public enum VerificationChannel {
        Email,
        Sms,
        Authenticator,
        Custom
    }
}