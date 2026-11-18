using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Service.ExternalLoginProviders {
    public class GoogleExternalLoginProvider<TUser> : IExternalLoginProvider<TUser>
        where TUser : class, new() {
        private readonly IOptions<GoogleExternalLoginOption<TUser>> _options;

        public GoogleExternalLoginProvider(IOptions<GoogleExternalLoginOption<TUser>> options) {
            _options = options;
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
            } catch(Exception) {
                // Provider validation exceptions may contain token-related details; never log them.
                return null;
            }
        }
    }
}