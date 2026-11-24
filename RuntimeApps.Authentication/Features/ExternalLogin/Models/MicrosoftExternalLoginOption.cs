using RuntimeApps.Authentication.Shared.Models;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Features.ExternalLogin.Models {
    public class MicrosoftExternalLoginOption<TUser>: BaseExternalLoginOption
        where TUser : class, new() {
        public MicrosoftExternalLoginOption() {
            // Microsoft email claims are mutable and are not proof of mailbox ownership, especially with
            // the multi-tenant "common" endpoint. Applications opt in explicitly (see the README).
            EmailTrust = ExternalLoginEmailTrustMode.Never;
        }

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
