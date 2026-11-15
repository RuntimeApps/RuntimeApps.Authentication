namespace RuntimeApps.Authentication.Model {
    public sealed class RefreshTokenOptions {
        /// <summary>Maximum lifetime of a refresh token. Defaults to 30 days.</summary>
        public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromDays(30);

        /// <summary>Revoke the affected session family when a previously rotated token is reused.</summary>
        public bool RevokeFamilyOnReuse { get; set; } = true;
    }
}