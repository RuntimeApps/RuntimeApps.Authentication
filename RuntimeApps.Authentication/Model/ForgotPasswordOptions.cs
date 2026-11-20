namespace RuntimeApps.Authentication.Model {
    public sealed class ForgotPasswordOptions {
        public const string SectionName = "Authentication:ForgotPassword";
        public ForgotPasswordMethod Method { get; set; } = ForgotPasswordMethod.VerificationCode;
        /// <summary>Frontend page that receives reset credentials in the URL fragment. Required for link mode.</summary>
        public string FrontendResetUrl { get; set; }
        public void Validate() {
            if(!Enum.IsDefined(Method))
                throw new InvalidOperationException("The password recovery method is invalid.");
            if(Method == ForgotPasswordMethod.Link &&
               (!Uri.TryCreate(FrontendResetUrl, UriKind.Absolute, out var uri) ||
                uri.Scheme != Uri.UriSchemeHttps ||
                string.IsNullOrEmpty(uri.Host) ||
                !string.IsNullOrEmpty(uri.UserInfo)))
                throw new InvalidOperationException("A valid absolute frontend reset URL is required for link-based password recovery.");
        }
    }
}