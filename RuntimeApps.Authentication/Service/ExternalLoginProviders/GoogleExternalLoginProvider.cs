using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Service.ExternalLoginProviders {
    public class GoogleExternalLoginProvider<TUser>: IExternalLoginProvider<TUser>
        where TUser : class, new() {
        private readonly ILogger<GoogleExternalLoginProvider<TUser>> _logger;
        private readonly IOptions<GoogleExternalLoginOption<TUser>> _option;

        public GoogleExternalLoginProvider(ILogger<GoogleExternalLoginProvider<TUser>> logger, IOptions<GoogleExternalLoginOption<TUser>> option) {
            _logger = logger;
            _option = option;
        }

        public string Provider => "GOOGLE";

        public async Task<ExternalLoginProviderResult<TUser>> ValidateAsync(string token) {
            try {
                var option = _option.Value;
                var settings = new GoogleJsonWebSignature.ValidationSettings() {
                    Audience = new List<string>() { option.ClientId }
                };
                GoogleJsonWebSignature.Payload payload = await GoogleJsonWebSignature.ValidateAsync(token, settings);
                var user = option.Mapper(payload);
                var userLogin = new UserLoginInfo(Provider, payload.Subject, Provider);
                return new ExternalLoginProviderResult<TUser> {\n                    User = user,\n                    LoginInfo = userLogin,\n                    Email = payload.Email,\n                    EmailVerified = payload.EmailVerified,\n                    HostedDomain = payload.HostedDomain\n                };
            } catch(Exception ex) {
                _logger.LogError(ex, ex.Message);
                return (null, null);
            }
        }
    }
}
