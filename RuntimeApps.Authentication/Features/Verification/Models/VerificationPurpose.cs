namespace RuntimeApps.Authentication.Features.Verification.Models {
    /// <summary>Identifies the operation for which a verification request was created.</summary>
    public enum VerificationPurpose {
        Registration,
        PasswordReset,
        TwoFactor,
        EmailChange,
        PhoneChange,
        Custom
    }
}
