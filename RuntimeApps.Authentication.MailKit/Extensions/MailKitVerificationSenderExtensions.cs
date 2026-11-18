using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.MailKit.Model;
using RuntimeApps.Authentication.MailKit.Service;

namespace RuntimeApps.Authentication.MailKit.Extensions {
    public static class MailKitVerificationSenderExtensions {
        public static IServiceCollection AddMailKitVerificationSender<TUser, TKey>(
            this IServiceCollection services,
            Action<SmtpVerificationOptions> configure)
            where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(configure);

            services.AddOptions<SmtpVerificationOptions>()
                .Configure(configure)
                .Validate(options => options.IsValid(), "SMTP verification options are invalid.")
                .ValidateOnStart();

            services.Replace(ServiceDescriptor.Scoped<
                IVerificationSender<TUser, TKey>,
                MailKitVerificationSender<TUser, TKey>>());
            return services;
        }
    }
}