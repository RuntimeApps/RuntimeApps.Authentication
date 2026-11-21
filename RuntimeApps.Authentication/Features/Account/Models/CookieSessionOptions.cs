namespace RuntimeApps.Authentication.Features.Account.Models {
    public sealed class CookieSessionOptions {
        public bool IsPersistent { get; set; }
        public string Scheme { get; set; } = Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme;
    }
}
