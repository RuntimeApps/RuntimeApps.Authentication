using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.Identity;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.Test {
    public class UserManagerDependencyInjectionTest {
        [Fact]
        public void Managers_AreSharedWithinScope_AndScopedAcrossScopes() {
            using var provider = CreateServices().BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
            using var firstScope = provider.CreateScope();
            using var secondScope = provider.CreateScope();

            var manager = firstScope.ServiceProvider.GetRequiredService<RuntimeAppsUserManager<IdentityUser>>();
            AssertManagerAliases(firstScope.ServiceProvider, manager);
            Assert.Same(manager, firstScope.ServiceProvider.GetRequiredService<RuntimeAppsUserManager<IdentityUser>>());

            var secondManager = secondScope.ServiceProvider.GetRequiredService<RuntimeAppsUserManager<IdentityUser>>();
            Assert.NotSame(manager, secondManager);
            AssertManagerAliases(secondScope.ServiceProvider, secondManager);
        }

        [Fact]
        public void ConsumerRegisteredDerivedNativeManager_IsPreservedAndShared() {
            var services = new ServiceCollection();
            AddStore(services);
            services.AddScoped<CustomUserManager>();
            services.AddScoped<UserManager<IdentityUser>>(sp => sp.GetRequiredService<CustomUserManager>());
            services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();

            using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
            using var scope = provider.CreateScope();
            var customManager = scope.ServiceProvider.GetRequiredService<CustomUserManager>();

            AssertManagerAliases(scope.ServiceProvider, customManager);
            Assert.Same(customManager, scope.ServiceProvider.GetRequiredService<CustomUserManager>());
        }

        [Fact]
        public void IdentityCoreDefaultManager_IsAliasedToRuntimeAppsManager() {
            var services = new ServiceCollection();
            AddStore(services);
            services.AddIdentityCore<IdentityUser>();
            services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();

            using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
            using var scope = provider.CreateScope();
            var manager = scope.ServiceProvider.GetRequiredService<RuntimeAppsUserManager<IdentityUser>>();

            AssertManagerAliases(scope.ServiceProvider, manager);
        }

        [Fact]
        public void AddUserManager_UsesDerivedManagerForAllRegistrations() {
            var services = CreateServices();
            var builder = services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();
            builder.AddUserManager<CustomUserManager>();

            using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
            using var scope = provider.CreateScope();
            var customManager = scope.ServiceProvider.GetRequiredService<CustomUserManager>();

            AssertManagerAliases(scope.ServiceProvider, customManager);
        }

        private static ServiceCollection CreateServices() {
            var services = new ServiceCollection();
            AddStore(services);
            services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();
            return services;
        }

        private static void AddStore(IServiceCollection services) {
            services.AddSingleton<IUserStore<IdentityUser>>(Mock.Of<IUserStore<IdentityUser>>());
            services.AddSingleton<IRoleStore<IdentityRole>>(Mock.Of<IRoleStore<IdentityRole>>());
        }

        private static void AssertManagerAliases(IServiceProvider services, RuntimeAppsUserManager<IdentityUser> manager) {
            Assert.Same(manager, services.GetRequiredService<RuntimeAppsUserManager<IdentityUser>>());
            Assert.Same(manager, services.GetRequiredService<IUserManager<IdentityUser>>());
            Assert.Same(manager, services.GetRequiredService<IUserPasswordManager<IdentityUser>>());
            Assert.Same(manager, services.GetRequiredService<IUserEmailManager<IdentityUser>>());
            Assert.Same(manager, services.GetRequiredService<IUserPhoneNumberManager<IdentityUser>>());
            Assert.Same(manager, services.GetRequiredService<IUserLoginManager<IdentityUser>>());
            Assert.Same(manager, services.GetRequiredService<IUserClaimManager<IdentityUser>>());
            Assert.Same(manager, services.GetRequiredService<IUserRoleManager<IdentityUser>>());
            Assert.Same(manager, services.GetRequiredService<IUserTwoFactorManager<IdentityUser>>());
            Assert.Same(manager, services.GetRequiredService<IUserLockoutManager<IdentityUser>>());
            Assert.Same(manager, services.GetRequiredService<IUserTokenManager<IdentityUser>>());
            Assert.Same(manager, services.GetRequiredService<UserManager<IdentityUser>>());
            Assert.Same(manager, services.GetRequiredService<SignInManager<IdentityUser>>().UserManager);
        }

        public sealed class CustomUserManager : RuntimeAppsUserManager<IdentityUser> {
            public CustomUserManager(
                IUserStore<IdentityUser> store,
                IOptions<IdentityOptions> optionsAccessor,
                IPasswordHasher<IdentityUser> passwordHasher,
                IEnumerable<IUserValidator<IdentityUser>> userValidators,
                IEnumerable<IPasswordValidator<IdentityUser>> passwordValidators,
                ILookupNormalizer keyNormalizer,
                IdentityErrorDescriber errors,
                IServiceProvider services,
                ILogger<UserManager<IdentityUser>> logger)
                : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators,
                    keyNormalizer, errors, services, logger) {
            }
        }
    }
}
