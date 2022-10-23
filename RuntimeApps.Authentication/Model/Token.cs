namespace RuntimeApps.Authentication.Model {
    public class Token {
        public string AuthenticationToken { get; set; }
        public DateTimeOffset? ExpireDate { get; set; }
    }
}
