using Microsoft.AspNetCore.Http;

namespace RuntimeApps.Authentication.Features.RefreshTokens.Models {
    public sealed class RefreshTokenOptions {
        public const string SectionName = "Authentication:RefreshTokens";
        /// <summary>Maximum lifetime of a refresh token. Defaults to 30 days.</summary>
        public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromDays(30);

        /// <summary>Revoke the affected session family when a previously rotated token is reused.</summary>
        public bool RevokeFamilyOnReuse { get; set; } = true;

        /// <summary>Maximum refresh requests per minute per remote IP address.</summary>
        public int RefreshRequestsPerMinute { get; set; } = 30;

        /// <summary>Name of the refresh-token cookie used by cookie authentication.</summary>
        public string CookieName { get; set; } = "__Host-runtimeapps-refresh";

        /// <summary>Cookie path. The __Host- prefix requires the root path.</summary>
        public string CookiePath { get; set; } = "/";

        public SameSiteMode CookieSameSite { get; set; } = SameSiteMode.Strict;
        public bool CookieSecure { get; set; } = true;

        /// <summary>Additional exact origins permitted to use cookie-based refresh/logout endpoints.</summary>
        public IList<string> AllowedOrigins { get; set; } = new List<string>();
    }
}
