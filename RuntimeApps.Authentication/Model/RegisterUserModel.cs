namespace RuntimeApps.Authentication.Model {
    public class RegisterUserModel<TUser>
        where TUser : class {
        public TUser UserInfo { get; set; }
        public string Password { get; set; }
    }
}
