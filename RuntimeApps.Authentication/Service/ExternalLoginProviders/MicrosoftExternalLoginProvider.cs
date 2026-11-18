using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Service.ExternalLoginProviders {
    public class MicrosoftExternalLoginProvider<TUser> : IExternalLoginProvider<TUser>
        where TUser : class, new() {
        private readonly IOptions<MicrosoftExternalLoginOption<TUser>> _options;

        public MicrosoftExternalLoginProvider(IOptions<MicrosoftExternalLoginOption<TUser>> options) {
            _options = options;
        }

        public string Provider => "MICROSOFT";

        public async Task<ExternalLoginProviderResult<TUser>> ValidateAsync(string token) {
            var option = _options.Value;
            if(string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(option.ClientId) ||
               string.IsNullOrWhiteSpace(option.IssuerEndpoint) || string.IsNullOrWhiteSpace(option.ConfigurationAddress))
                return null;

            try {
                var issuerEndpoint = option.IssuerEndpoint.EndsWith("/", StringComparison.Ordinal)
                    ? option.IssuerEndpoint
                    : option.IssuerEndpoint + "/";
                var metadataAddress = new Uri(
                    new Uri(issuerEndpoint), option.ConfigurationAddress.TrimStart('/')).ToString();
                var configuration = await OpenIdConnectConfigurationRetriever.GetAsync(
                    metadataAddress, CancellationToken.None);

                var handler = new JwtSecurityTokenHandler();
                handler.ValidateToken(token, new TokenValidationParameters {
                    IssuerSigningKeys = configuration.SigningKeys,
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidAudience = option.ClientId,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    ClockSkew = TimeSpan.FromMinutes(2),
                    IssuerValidator = (issuer, securityToken, parameters) => {
                        var jwt = securityToken as JwtSecurityToken;
                        var tenantId = jwt?.Claims.FirstOrDefault(claim => claim.Type == "tid")?.Value;
                        if(!Guid.TryParse(tenantId, out var parsedTenantId))
                            throw new SecurityTokenInvalidIssuerException("The Microsoft identity token has no valid tenant identifier.");

                        var expectedIssuer = configuration.Issuer.Replace(
                            "{tenantid}", parsedTenantId.ToString(), StringComparison.OrdinalIgnoreCase);
                        if(!string.Equals(issuer, expectedIssuer, StringComparison.OrdinalIgnoreCase))
                            throw new SecurityTokenInvalidIssuerException("The Microsoft identity token issuer is invalid.");
                        return issuer;
                    }
                }, out var validatedToken);

                var jwtToken = validatedToken as JwtSecurityToken;
                var objectId = jwtToken?.Claims.FirstOrDefault(claim => claim.Type == "oid")?.Value;
                var tenantIdClaim = jwtToken?.Claims.FirstOrDefault(claim => claim.Type == "tid")?.Value;
                if(string.IsNullOrWhiteSpace(objectId) || string.IsNullOrWhiteSpace(tenantIdClaim))
                    return null;

                var user = option.Mapper(jwtToken);
                if(user == null)
                    return null;

                return new ExternalLoginProviderResult<TUser> {
                    User = user,
                    LoginInfo = new UserLoginInfo(Provider, $"{tenantIdClaim}:{objectId}", Provider),
                    Email = jwtToken.Claims.FirstOrDefault(claim => claim.Type == "email")?.Value,
                    // Microsoft email claims are mutable and do not prove mailbox ownership.
                    EmailVerified = false
                };
            } catch(SecurityTokenException) {
                return null;
            } catch(HttpRequestException) {
                return null;
            } catch(InvalidOperationException) {
                return null;
            }
        }
    }
}