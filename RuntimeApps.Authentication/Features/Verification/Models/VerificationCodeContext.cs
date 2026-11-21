namespace RuntimeApps.Authentication.Features.Verification.Models {
    public sealed class VerificationCodeContext<TUser, TKey> where TKey : IEquatable<TKey> {
        public TUser User { get; init; }
        public TKey UserId { get; init; }
        public TKey RequestId { get; init; }
        public VerificationPurpose Purpose { get; init; }
        public VerificationChannel Channel { get; init; }
        public string CustomPurpose { get; init; }
        public string CustomChannel { get; init; }
        public string Destination { get; init; }
        /// <summary>The public handle associated with this verification request.</summary>
        public string VerificationHandle { get; init; }
        /// <summary>Identifies whether the credential is a code or a link token.</summary>
        public VerificationTokenGeneratorType? TokenGeneratorType { get; init; }
        /// <summary>The frontend page that receives link credentials in its URL fragment.</summary>
        public string FrontendResetUrl { get; init; }

        /// <summary>Creates a frontend reset URL with the handle and token in its fragment.</summary>
        public string CreateVerificationUrl(string token) {
            ArgumentException.ThrowIfNullOrWhiteSpace(token);
            if(TokenGeneratorType != VerificationTokenGeneratorType.Link)
                throw new InvalidOperationException("A verification URL is only available for link credentials.");
            if(string.IsNullOrWhiteSpace(FrontendResetUrl) || string.IsNullOrWhiteSpace(VerificationHandle))
                throw new InvalidOperationException("The frontend reset URL or verification handle is not available.");

            var builder = new UriBuilder(FrontendResetUrl) {
                Fragment = $"handle={Uri.EscapeDataString(VerificationHandle)}&token={Uri.EscapeDataString(token)}"
            };
            return builder.Uri.ToString();
        }
    }
}
