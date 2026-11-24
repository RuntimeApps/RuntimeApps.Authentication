using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
namespace RuntimeApps.Authentication.Features.ExternalLogin.Providers {
    public class GoogleExternalLoginProvider<TUser>: IExternalLoginProvider<TUser>
        where TUser : class, new() {
        private readonly IOptions<GoogleExternalLoginOption<TUser>> _options;
        private readonly ILogger<GoogleExternalLoginProvider<TUser>> _logger;

        public GoogleExternalLoginProvider(
            IOptions<GoogleExternalLoginOption<TUser>> options,
            ILogger<GoogleExternalLoginProvider<TUser>> logger) {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public string Provider => "GOOGLE";

        /// <summary>
        /// Validates the Google ID token's signature, issuer, expiry and audience. The default
        /// implementation delegates to <see cref="GoogleJsonWebSignature"/> with the configured client ID
        /// as the only accepted audience. Overridable so the provider's own handling can be tested without
        /// reaching Google's certificate endpoint.
        /// </summary>
        protected virtual Task<GoogleJsonWebSignature.Payload> ValidatePayloadAsync(
            string token, string audience, CancellationToken cancellationToken) =>
            GoogleJsonWebSignature.ValidateAsync(token,
                new GoogleJsonWebSignature.ValidationSettings {
                    Audience = new[] { audience }
                });

        /// <remarks>The Google token validation library does not expose cancellation. Cancellation is checked before validation begins.</remarks>
        public async Task<ExternalLoginProviderResult<TUser>> ValidateAsync(string token, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            var option = _options.Value;
            if(string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(option.ClientId))
                return null;

            try {
                var payload = await ValidatePayloadAsync(token, option.ClientId, cancellationToken);

                if(payload == null || string.IsNullOrWhiteSpace(payload.Subject))
                    return null;

                var user = option.Mapper(payload);
                if(user == null)
                    return null;

                return new ExternalLoginProviderResult<TUser> {
                    User = user,
                    LoginInfo = new UserLoginInfo(Provider, payload.Subject, Provider),
                    Email = payload.Email,
                    EmailVerified = payload.EmailVerified,
                    HostedDomain = payload.HostedDomain
                };
            } catch(OperationCanceledException) {
                throw;
            } catch(Exception exception) {
                // Log the validation reason, but never log the supplied identity token.
                _logger.LogWarning(
                    "Google external token validation failed. {ExceptionType}: {Reason}",
                    exception.GetType().FullName,
                    exception.Message);
                return null;
            }
        }
    }
}
