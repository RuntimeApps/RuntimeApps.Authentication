using Microsoft.AspNetCore.Identity;
using RuntimeApps.Authentication.Model.Facebook;

namespace RuntimeApps.Authentication.Model {
    public class FacebookExternalLoginOption<TUser>: BaseExternalLoginOption
        where TUser : class, new() {
        public string AccessTokenUrl { get; set; } = "https://graph.facebook.com/oauth/access_token?client_id={0}&client_secret={1}&grant_type=client_credentials";
        public string DebugTokenUrl { get; set; } = "https://graph.facebook.com/debug_token?input_token={0}&access_token={1}";
        public Func<FacebookUserData, TUser> Mapper { get; set; } = (data) => new TUser();

        public static TIdentityUser UserIdentityMapper<TIdentityUser, TKey>(FacebookUserData data)
            where TIdentityUser : IdentityUser<TKey>, new()
            where TKey : IEquatable<TKey> {
            return new TIdentityUser() {
                UserName = data.Email,
                Email = data.Email
            };
        }
    }
}
