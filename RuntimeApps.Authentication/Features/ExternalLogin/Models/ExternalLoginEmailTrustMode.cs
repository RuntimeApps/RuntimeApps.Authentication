namespace RuntimeApps.Authentication.Features.ExternalLogin.Models {
    /// <summary>
    /// Controls whether <see cref="Services.DefaultExternalLoginEmailTrustPolicy{TUser}"/> accepts the
    /// email claim returned by an external provider. A trusted email may be used to link the external
    /// identity to an existing local account and to create a confirmed account.
    /// </summary>
    public enum ExternalLoginEmailTrustMode {
        /// <summary>
        /// Trust only email claims the provider asserts are verified. Google additionally requires a
        /// Gmail/Googlemail address or an address in the token's hosted domain. Providers that do not
        /// assert verification (and custom providers) are never trusted in this mode.
        /// </summary>
        Verified = 0,
        /// <summary>
        /// Trust any non-empty email claim from the provider. Use only when the provider guarantees that
        /// the claim proves mailbox ownership.
        /// </summary>
        Always = 1,
        /// <summary>Never trust email claims from the provider.</summary>
        Never = 2
    }
}
