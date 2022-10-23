using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;
using RuntimeApps.Authentication.Model.Facebook;

namespace RuntimeApps.Authentication.Service.ExternalLoginProviders {
    public class FacebookExternalLoginProvider<TUser>: IExternalLoginProvider<TUser>
        where TUser : class, new() {
        private readonly IOptions<FacebookExternalLoginOption<TUser>> _options;

        public FacebookExternalLoginProvider(IOptions<FacebookExternalLoginOption<TUser>> options) {
            _options = options;
        }

        public string Provider => "FACEBOOK";

        public async Task<(TUser, UserLoginInfo)> ValidateAsync(string token) {
            var option = _options.Value;
            using HttpClient httpClient = new HttpClient();

            var appAccessTokenResponse = await httpClient.GetStringAsync(string.Format(option.AccessTokenUrl, option.ClientId, option.ClientSecret));
            var appAccessToken = JsonConvert.DeserializeObject<FacebookAppAccessToken>(appAccessTokenResponse);

            // 2. validate the user access token
            var userAccessTokenValidationResponse = await httpClient.GetStringAsync(string.Format(option.DebugTokenUrl, token, appAccessToken.Access_token));
            var userAccessTokenValidation = JsonConvert.DeserializeObject<FacebookUserAccessTokenValidation>(userAccessTokenValidationResponse);

            if(!userAccessTokenValidation.Data.Is_valid) {
                return (null, null);
            }

            // 3. we've got a valid token so we can request user data from fb
            var userInfoResponse = await httpClient.GetStringAsync($"https://graph.facebook.com/v2.8/me?fields=id,email,first_name,last_name,name,gender,locale,birthday,picture&access_token={token}");
            var userInfo = JsonConvert.DeserializeObject<FacebookUserData>(userInfoResponse);

            var user = option.Mapper(userInfo);
            var loginInfo = new UserLoginInfo(Provider, userInfo.Id.ToString(), Provider);
            return (user, loginInfo);
        }
    }
}
