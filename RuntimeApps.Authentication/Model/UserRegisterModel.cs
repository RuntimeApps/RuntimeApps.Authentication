using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Model {
    public class UserRegisterModel<TUser, TKey>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey> {
        public TUser UserInfo { get; set; }
        public string Password { get; set; }
    }
}
