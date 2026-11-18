namespace RuntimeApps.Authentication.Model {
    public enum VerificationRequestStatus {
        Pending,
        Completed,
        Locked,
        Expired,
        Superseded
    }
}