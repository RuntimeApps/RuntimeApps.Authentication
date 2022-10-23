using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Service.ExternalLoginProviders {
    public class MicrosoftExternalLoginProvider<TUser>: IExternalLoginProvider<TUser>
        where TUser : class, new() {
        private readonly IOptions<MicrosoftExternalLoginOption<TUser>> _options;

        public MicrosoftExternalLoginProvider(IOptions<MicrosoftExternalLoginOption<TUser>> options) {
            _options = options;
        }

        public string Provider => "MICROSOFT";

        public async Task<(TUser, UserLoginInfo)> ValidateAsync(string token) {
            var option = _options.Value;

            var openidConfiguration = await OpenIdConnectConfigurationRetriever.GetAsync(
                    $"{option.IssuerEndpoint}{option.ConfigurationAddress}", CancellationToken.None);


            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.ValidateToken(token, new TokenValidationParameters {
                IssuerSigningKeys = openidConfiguration.SigningKeys,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false
            }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            var user = option.Mapper(jwtToken);
            var loginInfo = new UserLoginInfo(Provider, jwtToken.Claims.FirstOrDefault(x => x.Type == "oid")?.Value, Provider);
            return (user, loginInfo);
        }
    }
}
