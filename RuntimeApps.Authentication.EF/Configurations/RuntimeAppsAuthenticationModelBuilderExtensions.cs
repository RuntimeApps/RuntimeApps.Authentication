using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.EF.Features.RefreshTokens.Configurations;
using RuntimeApps.Authentication.EF.Features.Verification.Configurations;
namespace RuntimeApps.Authentication.EF.Configurations {
    /// <summary>Selects which RuntimeApps authentication features add entities to the model.</summary>
    public sealed class RuntimeAppsAuthenticationModelOptions {
        internal bool RefreshTokensEnabled { get; private set; }
        internal bool VerificationRequestsEnabled { get; private set; }

        /// <summary>Adds the refresh-token entity (same as <c>AddRefreshTokenEntity</c>).</summary>
        public RuntimeAppsAuthenticationModelOptions UseRefreshTokens() {
            RefreshTokensEnabled = true;
            return this;
        }

        /// <summary>Adds the verification request and send entities (same as <c>AddVerificationRequestEntity</c>).</summary>
        public RuntimeAppsAuthenticationModelOptions UseVerificationRequests() {
            VerificationRequestsEnabled = true;
            return this;
        }
    }

    public static class RuntimeAppsAuthenticationModelBuilderExtensions {
        /// <summary>
        /// Adds the entities of the selected RuntimeApps authentication features in one call. The granular
        /// <c>AddRefreshTokenEntity</c> and <c>AddVerificationRequestEntity</c> methods remain available.
        /// Table names or schemas can be overridden afterwards with standard EF Core fluent calls.
        /// </summary>
        public static ModelBuilder AddRuntimeAppsAuthenticationEntities<TKey>(
            this ModelBuilder modelBuilder,
            Action<RuntimeAppsAuthenticationModelOptions> configure)
            where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(modelBuilder);
            ArgumentNullException.ThrowIfNull(configure);

            var options = new RuntimeAppsAuthenticationModelOptions();
            configure(options);
            if(!options.RefreshTokensEnabled && !options.VerificationRequestsEnabled)
                throw new InvalidOperationException(
                    "Select at least one feature, for example options.UseRefreshTokens() or options.UseVerificationRequests().");

            if(options.RefreshTokensEnabled)
                modelBuilder.AddRefreshTokenEntity<TKey>();
            if(options.VerificationRequestsEnabled)
                modelBuilder.AddVerificationRequestEntity<TKey>();
            return modelBuilder;
        }
    }
}
