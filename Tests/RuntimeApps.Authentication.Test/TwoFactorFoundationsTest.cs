using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Moq;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.EF.DependencyInjection;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;
using RuntimeApps.Authentication.Features.TwoFactor.Services;
using RuntimeApps.Authentication.Identity.Contracts;

namespace RuntimeApps.Authentication.Test;

public class TwoFactorFoundationsTest {
    // ---- options ----

    [Fact]
    public void Options_RequireIssuer() {
        Assert.Throws<InvalidOperationException>(() => new TwoFactorOptions().Validate());
        Assert.Throws<InvalidOperationException>(() => new TwoFactorOptions { Issuer = "  " }.Validate());
    }

    [Fact]
    public void Options_AcceptIssuerWithSafeDefaults() {
        var options = new TwoFactorOptions { Issuer = "Acme App" };

        options.Validate();

        Assert.Equal(TimeSpan.FromMinutes(5), options.ChallengeLifetime);
        Assert.Equal(5, options.MaxAttemptsPerChallenge);
        Assert.Equal(5, options.MaxPendingChallengesPerUser);
    }

    [Theory]
    [InlineData("Acme:App")]
    [InlineData("Acme\nApp")]
    public void Options_RejectUnsafeIssuer(string issuer) =>
        Assert.Throws<InvalidOperationException>(() => new TwoFactorOptions { Issuer = issuer }.Validate());

    [Fact]
    public void Options_RejectOverlongIssuer() =>
        Assert.Throws<InvalidOperationException>(() => new TwoFactorOptions { Issuer = new string('a', 101) }.Validate());

    [Theory]
    [InlineData(0)]
    [InlineData(29)]
    [InlineData(901)]
    public void Options_RejectChallengeLifetimeOutOfRange(int seconds) =>
        Assert.Throws<InvalidOperationException>(() =>
            new TwoFactorOptions { Issuer = "Acme", ChallengeLifetime = TimeSpan.FromSeconds(seconds) }.Validate());

    [Theory]
    [InlineData(0)]
    [InlineData(11)]
    public void Options_RejectAttemptLimitOutOfRange(int attempts) =>
        Assert.Throws<InvalidOperationException>(() =>
            new TwoFactorOptions { Issuer = "Acme", MaxAttemptsPerChallenge = attempts }.Validate());

    [Theory]
    [InlineData(0)]
    [InlineData(21)]
    public void Options_RejectPendingLimitOutOfRange(int pending) =>
        Assert.Throws<InvalidOperationException>(() =>
            new TwoFactorOptions { Issuer = "Acme", MaxPendingChallengesPerUser = pending }.Validate());

    // ---- registration ----

    [Fact]
    public void WithoutAddTwoFactor_NothingIsRegistered_AndBehaviorIsUnchanged() {
        using var provider = CreateServices().BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope = provider.CreateScope();

        Assert.Empty(scope.ServiceProvider.GetServices<ITwoFactorMethod<IdentityUser>>());
        Assert.DoesNotContain(provider.GetServices<IHostedService>(), s => IsMethodsValidator(s));
        Assert.False(provider.GetRequiredService<IOptions<IdentityOptions>>().Value.Tokens.ProviderMap
            .ContainsKey(TokenOptions.DefaultAuthenticatorProvider));
    }

    [Fact]
    public void AddTwoFactor_RegistersAuthenticatorProviderAndMethod() {
        var services = CreateServices();
        Builder(services).AddTwoFactor(o => o.Issuer = "Acme");

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope = provider.CreateScope();

        var map = provider.GetRequiredService<IOptions<IdentityOptions>>().Value.Tokens.ProviderMap;
        Assert.Equal(typeof(AuthenticatorTokenProvider<IdentityUser>), map[TokenOptions.DefaultAuthenticatorProvider].ProviderType);
        var method = Assert.Single(scope.ServiceProvider.GetServices<ITwoFactorMethod<IdentityUser>>());
        Assert.IsType<AuthenticatorTwoFactorMethod<IdentityUser>>(method);
        Assert.Equal("authenticator", method.Name);
        Assert.False(method.IsDeliveryBased);
        Assert.Equal("Acme", provider.GetRequiredService<IOptions<TwoFactorOptions>>().Value.Issuer);
    }

    [Fact]
    public void AddTwoFactor_CalledTwice_DoesNotDuplicateMethodOrValidator() {
        var services = CreateServices();
        Builder(services).AddTwoFactor(o => o.Issuer = "Acme").AddTwoFactor(o => o.MaxAttemptsPerChallenge = 3);

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope = provider.CreateScope();

        Assert.Single(scope.ServiceProvider.GetServices<ITwoFactorMethod<IdentityUser>>());
        Assert.Single(provider.GetServices<IHostedService>(), s => IsMethodsValidator(s));
        Assert.Equal(3, provider.GetRequiredService<IOptions<TwoFactorOptions>>().Value.MaxAttemptsPerChallenge);
    }

    [Fact]
    public void AddTwoFactor_BindsConfigurationThenCodeOverrides() {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            [$"{TwoFactorOptions.SectionName}:Issuer"] = "Configured",
            [$"{TwoFactorOptions.SectionName}:MaxAttemptsPerChallenge"] = "3",
            [$"{TwoFactorOptions.SectionName}:MaxPendingChallengesPerUser"] = "7"
        }).Build();
        var services = CreateServices();
        Builder(services).AddTwoFactor(configuration, o => o.MaxPendingChallengesPerUser = 2);

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<TwoFactorOptions>>().Value;

        Assert.Equal("Configured", options.Issuer);
        Assert.Equal(3, options.MaxAttemptsPerChallenge);
        Assert.Equal(2, options.MaxPendingChallengesPerUser);
    }

    [Fact]
    public void AddTwoFactor_WithoutIssuer_FailsOptionsValidation() {
        var services = CreateServices();
        Builder(services).AddTwoFactor(_ => { });

        using var provider = services.BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<TwoFactorOptions>>().Value);
    }

    [Fact]
    public void AddTwoFactor_KeepsDeveloperSuppliedAuthenticatorProvider() {
        var services = CreateServices();
        services.Configure<IdentityOptions>(o => o.Tokens.ProviderMap[TokenOptions.DefaultAuthenticatorProvider] =
            new TokenProviderDescriptor(typeof(CustomAuthenticatorProvider)));
        Builder(services).AddTwoFactor(o => o.Issuer = "Acme");

        using var provider = services.BuildServiceProvider();

        Assert.Equal(typeof(CustomAuthenticatorProvider),
            provider.GetRequiredService<IOptions<IdentityOptions>>().Value.Tokens.ProviderMap[TokenOptions.DefaultAuthenticatorProvider].ProviderType);
    }

    [Fact]
    public void TwoFactorManager_ResolvesToSharedUserManager() {
        var services = CreateServices();
        Builder(services).AddTwoFactor(o => o.Issuer = "Acme");

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope = provider.CreateScope();

        Assert.Same(scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>(),
            scope.ServiceProvider.GetRequiredService<IUserTwoFactorManager<IdentityUser>>());
    }

    // ---- custom methods ----

    [Fact]
    public async Task CustomMethod_IsRegisteredOnceAlongsideAuthenticator() {
        var services = CreateServices();
        Builder(services).AddTwoFactor(o => o.Issuer = "Acme").AddTwoFactorMethod<FakeSmsMethod>().AddTwoFactorMethod<FakeSmsMethod>();

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope = provider.CreateScope();
        var names = scope.ServiceProvider.GetServices<ITwoFactorMethod<IdentityUser>>().Select(m => m.Name).Order().ToArray();

        Assert.Equal(new[] { "authenticator", "sms" }, names);
        await RunMethodsValidatorAsync(provider);
    }

    [Fact]
    public async Task Startup_RejectsDuplicateMethodNames() {
        var services = CreateServices();
        Builder(services).AddTwoFactor(o => o.Issuer = "Acme").AddTwoFactorMethod<DuplicateAuthenticatorMethod>();

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => RunMethodsValidatorAsync(provider));
        Assert.Contains("authenticator", exception.Message);
    }

    [Theory]
    [InlineData("Bad Name")]
    [InlineData("sms\n")]
    [InlineData("")]
    public async Task Startup_RejectsInvalidMethodNames(string name) {
        var services = CreateServices();
        Builder(services).AddTwoFactor(o => o.Issuer = "Acme");
        services.AddScoped<ITwoFactorMethod<IdentityUser>>(_ => new NamedMethod(name));

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

        await Assert.ThrowsAsync<InvalidOperationException>(() => RunMethodsValidatorAsync(provider));
    }

    [Fact]
    public async Task DeliveryMethodDefault_SendChallengeIsNotSupportedForNonDeliveryMethods() {
        ITwoFactorMethod<IdentityUser> method = new AuthenticatorTwoFactorMethod<IdentityUser>(
            Mock.Of<IUserTwoFactorManager<IdentityUser>>(), CreateUserManagerMock().Object,
            Options.Create(new TwoFactorOptions { Issuer = "Acme" }));

        await Assert.ThrowsAsync<NotSupportedException>(() => method.SendChallengeAsync(new IdentityUser(), CancellationToken.None));
    }

    // ---- authenticator method ----

    [Theory]
    [InlineData("123456")]
    [InlineData(" 123 456 ")]
    [InlineData("123-456")]
    public async Task Verify_NormalizesCodeBeforeCallingTokenProvider(string input) {
        var manager = new Mock<IUserTwoFactorManager<IdentityUser>>(MockBehavior.Strict);
        manager.Setup(m => m.VerifyTwoFactorTokenAsync(It.IsAny<IdentityUser>(), TokenOptions.DefaultAuthenticatorProvider, "123456"))
            .ReturnsAsync(true);
        var method = CreateMethod(manager);

        Assert.True(await method.VerifyAsync(new IdentityUser(), input, CancellationToken.None));

        manager.Verify(m => m.VerifyTwoFactorTokenAsync(It.IsAny<IdentityUser>(), TokenOptions.DefaultAuthenticatorProvider, "123456"), Times.Once);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12345a")]
    [InlineData("\uFF11\uFF12\uFF13\uFF14\uFF15\uFF16")] // full-width digits
    [InlineData("123456\n7")]
    [InlineData("+12345")]
    public async Task Verify_MalformedCode_NeverReachesTokenProvider(string input) {
        var manager = new Mock<IUserTwoFactorManager<IdentityUser>>(MockBehavior.Strict);
        var method = CreateMethod(manager);

        Assert.False(await method.VerifyAsync(new IdentityUser(), input, CancellationToken.None));

        manager.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Methods_HonorAlreadyCancelledToken() {
        var manager = new Mock<IUserTwoFactorManager<IdentityUser>>(MockBehavior.Strict);
        var method = CreateMethod(manager);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => method.VerifyAsync(new IdentityUser(), "123456", cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => method.BeginEnrollmentAsync(new IdentityUser(), cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => method.IsEnrolledAsync(new IdentityUser(), cts.Token));
        manager.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Authenticator_EnrollmentRoundTrip_WithRealIdentityStore() {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(cancellationToken);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<TwoFactorDbContext>(o => o.UseSqlite(connection));
        Builder(services).AddEfStores<TwoFactorDbContext, IdentityUser, IdentityRole, string>().AddTwoFactor(o => o.Issuer = "Acme App");

        await using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope = provider.CreateScope();
        await scope.ServiceProvider.GetRequiredService<TwoFactorDbContext>().Database.EnsureCreatedAsync(cancellationToken);
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var user = new IdentityUser { UserName = "alice", Email = "alice@example.com" };
        Assert.True((await users.CreateAsync(user)).Succeeded);
        var method = scope.ServiceProvider.GetServices<ITwoFactorMethod<IdentityUser>>().Single();

        Assert.False(await method.IsEnrolledAsync(user, cancellationToken));

        var info = await method.BeginEnrollmentAsync(user, cancellationToken);
        var key = info.Properties[AuthenticatorTwoFactorMethod<IdentityUser>.SharedKeyProperty].Replace(" ", "");
        var uri = info.Properties[AuthenticatorTwoFactorMethod<IdentityUser>.AuthenticatorUriProperty];

        Assert.Equal("authenticator", info.Method);
        Assert.Equal($"otpauth://totp/Acme%20App:alice%40example.com?secret={key}&issuer=Acme%20App&digits=6", uri);
        Assert.Equal(await users.GetAuthenticatorKeyAsync(user), key);

        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var validCodes = Enumerable.Range(-2, 5).Select(offset => ComputeTotp(key, step + offset)).ToHashSet();
        var wrong = Enumerable.Range(0, 1_000_000).Select(i => i.ToString("D6")).First(c => !validCodes.Contains(c));

        Assert.False(await method.ConfirmEnrollmentAsync(user, wrong, cancellationToken));
        Assert.True(await method.ConfirmEnrollmentAsync(user, ComputeTotp(key, step), cancellationToken));
        Assert.True(await method.VerifyAsync(user, ComputeTotp(key, step).Insert(3, " "), cancellationToken));
        Assert.False(await method.IsEnrolledAsync(user, cancellationToken)); // confirmation alone does not enable 2FA

        Assert.True((await users.SetTwoFactorEnabledAsync(user, true)).Succeeded);
        Assert.True(await method.IsEnrolledAsync(user, cancellationToken));
        await Assert.ThrowsAsync<InvalidOperationException>(() => method.BeginEnrollmentAsync(user, cancellationToken));
        Assert.Equal(key, await users.GetAuthenticatorKeyAsync(user)); // enrolled key was not rotated
    }

    // ---- helpers ----

    private static ServiceCollection CreateServices() {
        var services = new ServiceCollection();
        services.AddSingleton<IUserStore<IdentityUser>>(Mock.Of<IUserStore<IdentityUser>>());
        services.AddSingleton<IRoleStore<IdentityRole>>(Mock.Of<IRoleStore<IdentityRole>>());
        return services;
    }

    private static RuntimeAppsAuthenticationBuilder<IdentityUser, IdentityRole, string> Builder(IServiceCollection services) =>
        services.AddAuthentication().AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>();

    private static AuthenticatorTwoFactorMethod<IdentityUser> CreateMethod(Mock<IUserTwoFactorManager<IdentityUser>> manager) =>
        new(manager.Object, CreateUserManagerMock().Object, Options.Create(new TwoFactorOptions { Issuer = "Acme" }));

    private static Mock<UserManager<IdentityUser>> CreateUserManagerMock() =>
        new(Mock.Of<IUserStore<IdentityUser>>(), null, null, null, null, null, null, null, null);

    private static bool IsMethodsValidator(IHostedService service) =>
        service.GetType().Name.StartsWith("TwoFactorMethodsStartupValidator", StringComparison.Ordinal);

    private static Task RunMethodsValidatorAsync(IServiceProvider provider) =>
        provider.GetServices<IHostedService>().Single(IsMethodsValidator).StartAsync(CancellationToken.None);

    /// <summary>RFC 6238 TOTP (HMAC-SHA1, 30 s step, 6 digits) matching Identity's authenticator provider.</summary>
    private static string ComputeTotp(string base32Key, long step) {
        var counter = BitConverter.GetBytes(step);
        if(BitConverter.IsLittleEndian) Array.Reverse(counter);
        using var hmac = new HMACSHA1(DecodeBase32(base32Key));
        var hash = hmac.ComputeHash(counter);
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6");
    }

    private static byte[] DecodeBase32(string value) {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bytes = new List<byte>();
        var buffer = 0;
        var bits = 0;
        foreach(var c in value.TrimEnd('=').ToUpperInvariant()) {
            buffer = (buffer << 5) | alphabet.IndexOf(c);
            bits += 5;
            if(bits >= 8) {
                bits -= 8;
                bytes.Add((byte)((buffer >> bits) & 0xFF));
            }
        }
        return bytes.ToArray();
    }

    public sealed class TwoFactorDbContext(DbContextOptions<TwoFactorDbContext> options)
        : IdentityDbContext<IdentityUser, IdentityRole, string>(options);

    public sealed class CustomAuthenticatorProvider : IUserTwoFactorTokenProvider<IdentityUser> {
        public Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<IdentityUser> manager, IdentityUser user) => Task.FromResult(false);
        public Task<string> GenerateAsync(string purpose, UserManager<IdentityUser> manager, IdentityUser user) => Task.FromResult("");
        public Task<bool> ValidateAsync(string purpose, string token, UserManager<IdentityUser> manager, IdentityUser user) => Task.FromResult(false);
    }

    public abstract class StubMethod(string name, bool delivery = false) : ITwoFactorMethod<IdentityUser> {
        public string Name => name;
        public bool IsDeliveryBased => delivery;
        public Task<bool> IsEnrolledAsync(IdentityUser user, CancellationToken cancellationToken) => Task.FromResult(false);
        public Task<TwoFactorEnrollmentInfo> BeginEnrollmentAsync(IdentityUser user, CancellationToken cancellationToken) =>
            Task.FromResult(new TwoFactorEnrollmentInfo(name, new Dictionary<string, string>()));
        public Task<bool> ConfirmEnrollmentAsync(IdentityUser user, string code, CancellationToken cancellationToken) => Task.FromResult(false);
        public Task SendChallengeAsync(IdentityUser user, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<bool> VerifyAsync(IdentityUser user, string code, CancellationToken cancellationToken) => Task.FromResult(false);
    }

    public sealed class FakeSmsMethod() : StubMethod("sms", true);
    public sealed class DuplicateAuthenticatorMethod() : StubMethod("authenticator");
    public sealed class NamedMethod(string name) : StubMethod(name);
}
