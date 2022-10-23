using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Model {
    public class MicrosoftExternalLoginOption<TUser>: BaseExternalLoginOption
        where TUser : class, new() {
        public string IssuerEndpoint { get; set; } = "https://login.microsoftonline.com/common/v2.0/";
        public string ConfigurationAddress { get; set; } = "/.well-known/openid-configuration";
        public Func<JwtSecurityToken, TUser> Mapper { get; set; } = (data) => new TUser();

        public static TIdentityUser UserIdentityMapper<TIdentityUser, TKey>(JwtSecurityToken data)
            where TIdentityUser : IdentityUser<TKey>, new()
            where TKey : IEquatable<TKey> {
            return new TIdentityUser() {
                UserName = data.Claims.FirstOrDefault(x => x.Type == "email")?.Value,
                Email = data.Claims.FirstOrDefault(x => x.Type == "email")?.Value
            };
        }
    }
}
