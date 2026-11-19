namespace RuntimeApps.Authentication.Model {
    public sealed class VerificationCodeContext<TUser, TKey> where TKey : IEquatable<TKey> {
        public TUser User { get; init; }
        public TKey UserId { get; init; }
        public TKey RequestId { get; init; }
        public VerificationPurpose Purpose { get; init; }
        public VerificationChannel Channel { get; init; }
        public string CustomPurpose { get; init; }
        public string CustomChannel { get; init; }
        public string Destination { get; init; }
    }
}