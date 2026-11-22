using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.EF.DependencyInjection;
using RuntimeApps.Authentication.Identity.Contracts;
namespace RuntimeApps.Authentication.Test {
    public class EfIdentityIntegrationTest {
        private const string Password = "P@ssw0rd!Test1";

        [Fact]
        public Task AddEfStores_WorksWithDefaultStringKeys() =>
            AssertRoundTripAsync<StringKeyDbContext, IdentityUser, IdentityRole, string>(
                new IdentityUser { UserName = "string-user" }, new IdentityRole("string-role"));

        [Fact]
        public Task AddEfStores_WorksWithIntKeys() =>
            AssertRoundTripAsync<IntKeyDbContext, IdentityUser<int>, IdentityRole<int>, int>(
                new IdentityUser<int> { UserName = "int-user" }, new IdentityRole<int> { Name = "int-role" });

        [Fact]
        public Task AddEfStores_WorksWithCustomUserAndRoleAndGuidKeys() =>
            AssertRoundTripAsync<GuidKeyDbContext, AppUser, AppRole, Guid>(
                new AppUser { UserName = "guid-user", DisplayName = "Guid User" }, new AppRole { Name = "guid-role" });

        [Fact]
        public Task AddEfStores_WorksWithPlainDbContextThatMapsIdentityEntities() =>
            AssertRoundTripAsync<PlainDbContext, IdentityUser<int>, IdentityRole<int>, int>(
                new IdentityUser<int> { UserName = "plain-user" }, new IdentityRole<int> { Name = "plain-role" });

        [Fact]
        public async Task StartupValidation_RejectsDbContextWithoutIdentityEntities() {
            await using var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddDbContext<EmptyDbContext>(options => options.UseSqlite(connection));
            services.AddAuthentication()
                .AddRuntimeAppsAuthentication<IdentityUser<int>, IdentityRole<int>, int>()
                .AddEfStores<EmptyDbContext, IdentityUser<int>, IdentityRole<int>, int>();

            await using var provider = services.BuildServiceProvider();
            var validator = Assert.Single(provider.GetServices<IHostedService>());
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(
                () => validator.StartAsync(TestContext.Current.CancellationToken));
            Assert.Contains("IdentityUserClaim", exception.Message);
        }

        private static async Task AssertRoundTripAsync<TDbContext, TUser, TRole, TKey>(TUser user, TRole role)
            where TDbContext : DbContext
            where TUser : IdentityUser<TKey>, new()
            where TRole : IdentityRole<TKey>
            where TKey : IEquatable<TKey> {
            var cancellationToken = TestContext.Current.CancellationToken;
            await using var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(cancellationToken);
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddDbContext<TDbContext>(options => options.UseSqlite(connection));
            services.AddAuthentication()
                .AddRuntimeAppsAuthentication<TUser, TRole, TKey>()
                .AddEfStores<TDbContext, TUser, TRole, TKey>();

            await using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
            foreach(var hosted in provider.GetServices<IHostedService>())
                await hosted.StartAsync(cancellationToken);

            using var scope = provider.CreateScope();
            await scope.ServiceProvider.GetRequiredService<TDbContext>().Database.EnsureCreatedAsync(cancellationToken);
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();
            var roles = scope.ServiceProvider.GetRequiredService<IRoleManager<TRole>>();

            Assert.True((await roles.CreateAsync(role)).Succeeded);
            Assert.True((await users.CreateAsync(user, Password)).Succeeded);
            Assert.True((await users.AddToRoleAsync(user, role.Name)).Succeeded);

            var found = await users.FindByNameAsync(user.UserName);
            Assert.NotNull(found);
            Assert.Contains(role.Name, await users.GetRolesAsync(found));
            Assert.True(await users.CheckPasswordAsync(found, Password));
        }

        public sealed class AppUser: IdentityUser<Guid> {
            public string DisplayName { get; set; }
        }

        public sealed class AppRole: IdentityRole<Guid> { }

        public sealed class StringKeyDbContext(DbContextOptions<StringKeyDbContext> options)
            : IdentityDbContext<IdentityUser, IdentityRole, string>(options);

        public sealed class IntKeyDbContext(DbContextOptions<IntKeyDbContext> options)
            : IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int>(options);

        public sealed class GuidKeyDbContext(DbContextOptions<GuidKeyDbContext> options)
            : IdentityDbContext<AppUser, AppRole, Guid>(options);

        public sealed class EmptyDbContext(DbContextOptions<EmptyDbContext> options): DbContext(options);

        /// <summary>A DbContext that does not derive from IdentityDbContext but maps the default Identity entities.</summary>
        public sealed class PlainDbContext(DbContextOptions<PlainDbContext> options): DbContext(options) {
            protected override void OnModelCreating(ModelBuilder modelBuilder) {
                modelBuilder.Entity<IdentityUser<int>>();
                modelBuilder.Entity<IdentityRole<int>>();
                modelBuilder.Entity<IdentityUserClaim<int>>();
                modelBuilder.Entity<IdentityRoleClaim<int>>();
                modelBuilder.Entity<IdentityUserRole<int>>().HasKey(item => new { item.UserId, item.RoleId });
                modelBuilder.Entity<IdentityUserLogin<int>>().HasKey(item => new { item.LoginProvider, item.ProviderKey });
                modelBuilder.Entity<IdentityUserToken<int>>().HasKey(item => new { item.UserId, item.LoginProvider, item.Name });
            }
        }
    }
}
