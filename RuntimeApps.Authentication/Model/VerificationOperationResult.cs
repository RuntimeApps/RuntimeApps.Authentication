namespace RuntimeApps.Authentication.Model {
    public sealed class VerificationOperationResult {
        public bool Succeeded { get; init; }
        public string VerificationHandle { get; init; }
        public DateTimeOffset? ExpiresAt { get; init; }
        public string ErrorCode { get; init; }
        public string ErrorDescription { get; init; }

        public static VerificationOperationResult Success(string handle, DateTimeOffset expiresAt) =>
            new() { Succeeded = true, VerificationHandle = handle, ExpiresAt = expiresAt };

        public static VerificationOperationResult Failure(string code, string description) =>
            new() { Succeeded = false, ErrorCode = code, ErrorDescription = description };
    }
}