namespace RuntimeApps.Authentication.Model {
    public class IdentityUserDto: IdentityUserDto<string> {

    }

    public class IdentityUserDto<TKey> where TKey : IEquatable<TKey> {
        public virtual TKey Id { get; set; }
        public virtual string UserName { get; set; }
        public virtual string Email { get; set; }
        public virtual string PhoneNumber { get; set; }
        public virtual bool TwoFactorEnabled { get; set; }
    }
}
