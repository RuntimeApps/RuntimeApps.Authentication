using MailKit.Security;

namespace RuntimeApps.Authentication.MailKit.Model {
    public sealed class SmtpVerificationOptions {
        public const string SectionName = "Authentication:Verification:Smtp";

        public string Host { get; set; }
        public int Port { get; set; } = 587;
        public SecureSocketOptions SocketOptions { get; set; } = SecureSocketOptions.StartTls;
        public string UserName { get; set; }
        public string Password { get; set; }
        public string FromAddress { get; set; }
        public string FromName { get; set; } = "Account verification";
        public string ApplicationName { get; set; } = "Application";

        public bool IsValid() =>
            !string.IsNullOrWhiteSpace(Host) &&
            Port is > 0 and <= 65535 &&
            !string.IsNullOrWhiteSpace(FromAddress) &&
            ((!string.IsNullOrWhiteSpace(UserName) && !string.IsNullOrEmpty(Password)) ||
             (string.IsNullOrWhiteSpace(UserName) && string.IsNullOrEmpty(Password)));
    }
}