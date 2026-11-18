using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;
using RuntimeApps.Authentication.Model.Facebook;

namespace RuntimeApps.Authentication.Service.ExternalLoginProviders {
    public class FacebookExternalLoginProvider<TUser> : IExternalLoginProvider<TUser>
        where TUser : class, new() {
        private readonly IOptions<FacebookExternalLoginOption<TUser>> _options;

        public FacebookExternalLoginProvider(IOptions<FacebookExternalLoginOption<TUser>> options) {
            _options = options;
        }

        public string Provider => "FACEBOOK";

        public async Task<ExternalLoginProviderResult<TUser>> ValidateAsync(string token) {
            var option = _options.Value;
            if(string.IsNullOrWhiteSpace(token) ||
               !long.TryParse(option.ClientId, NumberStyles.None, CultureInfo.InvariantCulture, out var configuredAppId))
                return null;

            var graphApiVersion = string.IsNullOrWhiteSpace(option.GraphApiVersion) ? "v27.0" : option.GraphApiVersion;
            if(!Regex.IsMatch(graphApiVersion, "^v[0-9]+\\.0$", RegexOptions.CultureInvariant))
                return null;

            try {
                using var client = new HttpClient();
                var appTokenUrl = string.Format(CultureInfo.InvariantCulture, option.AccessTokenUrl,
                    Uri.EscapeDataString(option.ClientId), Uri.EscapeDataString(option.ClientSecret));
                var appTokenResponse = await client.GetStringAsync(appTokenUrl);
                var appToken = JsonConvert.DeserializeObject<FacebookAppAccessToken>(appTokenResponse);
                if(string.IsNullOrWhiteSpace(appToken?.Access_token))
                    return null;

                var debugUrl = string.Format(CultureInfo.InvariantCulture, option.DebugTokenUrl,
                    Uri.EscapeDataString(token), Uri.EscapeDataString(appToken.Access_token));
                var debugResponse = await client.GetStringAsync(debugUrl);
                var debugData = JsonConvert.DeserializeObject<FacebookUserAccessTokenValidation>(debugResponse)?.Data;
                if(debugData == null || !debugData.Is_valid || debugData.App_id != configuredAppId ||
                   debugData.User_Id == null ||
                   (debugData.Expires_at is > 0 && DateTimeOffset.FromUnixTimeSeconds(debugData.Expires_at.Value) <= DateTimeOffset.UtcNow))
                    return null;

                var userUrl = $"https://graph.facebook.com/{graphApiVersion}/me?fields=id,email,first_name,last_name,name,gender,locale,birthday,picture&access_token={Uri.EscapeDataString(token)}";
                var userResponse = await client.GetStringAsync(userUrl);
                var userInfo = JsonConvert.DeserializeObject<FacebookUserData>(userResponse);
                if(userInfo?.Id == null || userInfo.Id.Value != debugData.User_Id.Value)
                    return null;

                var user = option.Mapper(userInfo);
                if(user == null)
                    return null;

                return new ExternalLoginProviderResult<TUser> {
                    User = user,
                    LoginInfo = new UserLoginInfo(Provider,
                        userInfo.Id.Value.ToString(CultureInfo.InvariantCulture), Provider),
                    Email = userInfo.Email,
                    // Facebook's current response model does not provide a trustworthy email-verified assertion.
                    EmailVerified = false
                };
            } catch(HttpRequestException) {
                return null;
            } catch(JsonException) {
                return null;
            } catch(FormatException) {
                return null;
            }
        }
    }
}