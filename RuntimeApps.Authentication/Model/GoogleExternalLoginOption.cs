using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Model {
    public class GoogleExternalLoginOption<TUser>: BaseExternalLoginOption
        where TUser : class, new() {
        public Func<GoogleJsonWebSignature.Payload, TUser> Mapper { get; set; } = (data) => new TUser();

        public static TIdentityUser UserIdentityMapper<TIdentityUser, TKey>(GoogleJsonWebSignature.Payload data)
            where TIdentityUser : IdentityUser<TKey>, new()
            where TKey : IEquatable<TKey> {
            return new TIdentityUser() {
                UserName = data.Email,
                Email = data.Email
            };
        }
    }
}
