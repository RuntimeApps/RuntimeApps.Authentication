using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.MailKit.Model;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.MailKit.Service {
    public sealed class MailKitVerificationSender<TUser, TKey> : IVerificationSender<TUser, TKey>
        where TKey : IEquatable<TKey> {
        private readonly SmtpVerificationOptions _options;

        public MailKitVerificationSender(IOptions<SmtpVerificationOptions> options) {
            _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
            if(!_options.IsValid())
                throw new InvalidOperationException("SMTP verification options are invalid.");
        }

        public async Task SendAsync(
            VerificationCodeContext<TUser, TKey> context,
            string code,
            DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default) {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentException.ThrowIfNullOrWhiteSpace(context.Destination);
            ArgumentException.ThrowIfNullOrWhiteSpace(code);

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(_options.FromName, _options.FromAddress));
            message.To.Add(MailboxAddress.Parse(context.Destination));
            message.Subject = $"{_options.ApplicationName} verification code";
            message.Body = new TextPart("plain") {
                Text = $"Your verification code is: {code}\n\n" +
                       $"This code expires at {expiresAt:O}. If you did not request this code, you can ignore this message."
            };

            using var client = new SmtpClient();
            await client.ConnectAsync(_options.Host, _options.Port, _options.SocketOptions, cancellationToken);
            if(!string.IsNullOrWhiteSpace(_options.UserName))
                await client.AuthenticateAsync(_options.UserName, _options.Password, cancellationToken);
            await client.SendAsync(message, cancellationToken);
            await client.DisconnectAsync(true, cancellationToken);
        }
    }
}