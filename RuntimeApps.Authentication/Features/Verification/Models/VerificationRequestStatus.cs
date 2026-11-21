namespace RuntimeApps.Authentication.Features.Verification.Models {
    public enum VerificationRequestStatus {
        Pending,
        Completed,
        Locked,
        Expired,
        Superseded
    }
}
