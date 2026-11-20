using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.PasswordRecovery.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.Registration.Contracts;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Sample.Model;
using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
using RuntimeApps.Authentication.Features.PasswordRecovery.Models;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Features.Registration.Models;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Identity.Models;
using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Sample.Services {
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
            var isPasswordReset = context.Purpose == VerificationPurpose.PasswordReset;
            var isPasswordResetLink = isPasswordReset &&
                                      context.TokenGeneratorType == VerificationTokenGeneratorType.Link;
            message.Subject = isPasswordReset
                ? $"{_options.ApplicationName} password reset"
                : $"{_options.ApplicationName} verification code";
            message.Body = new TextPart("plain") {
                Text = isPasswordResetLink
                    ? $"Use this link to reset your password: {context.CreateVerificationUrl(code)}\n\n" +
                      $"This link expires at {expiresAt:O}. If you did not request a password reset, you can ignore this message."
                    : $"{(isPasswordReset ? "Your password reset code" : "Your verification code")} is: {code}\n" +
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