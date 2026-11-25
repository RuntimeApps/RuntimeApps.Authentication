using Microsoft.AspNetCore.Http;

namespace RuntimeApps.Authentication.Features.RefreshTokens.Models {
    public sealed class RefreshTokenOptions {
        public const string SectionName = "Authentication:RefreshTokens";
        /// <summary>Maximum lifetime of a refresh token. Defaults to 30 days.</summary>
        public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromDays(30);

        /// <summary>
        /// Maximum lifetime of a whole session, measured from the login that created it. Rotation never
        /// extends it: the final refresh token of a session expires no later than this. Must be at least
        /// <see cref="TokenLifetime"/>. Defaults to 90 days.
        /// </summary>
        public TimeSpan AbsoluteSessionLifetime { get; set; } = TimeSpan.FromDays(90);

        /// <summary>
        /// How long a revoked, rotated or expired record is kept before cleanup may delete it. Retained records
        /// support security investigation and reuse detection. Must be at least <see cref="TokenLifetime"/> so
        /// that a consumed token is still recognised as reused for as long as it could have been valid.
        /// Defaults to 30 days.
        /// </summary>
        public TimeSpan CleanupRetention { get; set; } = TimeSpan.FromDays(30);

        /// <summary>
        /// Maximum number of records deleted by one cleanup call. Must be between 1 and 10000. Defaults to 1000.
        /// </summary>
        public int CleanupBatchSize { get; set; } = 1000;

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
