using System.Net.Mail;
using MailKit.Security;

namespace RuntimeApps.Authentication.Sample.Model {
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

        public bool IsValid() {
            if(string.IsNullOrWhiteSpace(Host) || Port is <= 0 or > 65535 ||
               string.IsNullOrWhiteSpace(FromAddress) ||
               !((!string.IsNullOrWhiteSpace(UserName) && !string.IsNullOrEmpty(Password)) ||
                 (string.IsNullOrWhiteSpace(UserName) && string.IsNullOrEmpty(Password))))
                return false;

            try {
                _ = new MailAddress(FromAddress);
                return true;
            } catch(FormatException) {
                return false;
            }
        }
    }
}