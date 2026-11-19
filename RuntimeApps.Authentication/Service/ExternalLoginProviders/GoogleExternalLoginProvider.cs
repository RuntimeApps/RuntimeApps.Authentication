using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Service.ExternalLoginProviders {
    public class GoogleExternalLoginProvider<TUser> : IExternalLoginProvider<TUser>
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

        public async Task<ExternalLoginProviderResult<TUser>> ValidateAsync(string token) {
            var option = _options.Value;
            if(string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(option.ClientId))
                return null;

            try {
                var payload = await GoogleJsonWebSignature.ValidateAsync(token,
                    new GoogleJsonWebSignature.ValidationSettings {
                        Audience = new[] { option.ClientId }
                    });

                if(string.IsNullOrWhiteSpace(payload.Subject))
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