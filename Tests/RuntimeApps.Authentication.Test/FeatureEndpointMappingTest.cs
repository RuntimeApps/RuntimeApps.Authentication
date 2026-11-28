using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using System.Text;
using RuntimeApps.Authentication.Endpoints.Account;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Features.Registration.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

public sealed class FeatureEndpointMappingTest {
    [Fact]
    public void AuthenticationMapping_DoesNotMapSessionEndpoints() {
        using var host = CreateHost(includeVerificationDependencies: false);

        host.Endpoints.MapGroup("api/auth")
            .MapAuthenticationApi<IdentityUser<int>, TestUserDto, int>();

        var endpoint = Assert.Single(Endpoints(host));
        Assert.Equal("api/auth/login", ((RouteEndpoint)endpoint).RoutePattern.RawText);
        Assert.IsAssignableFrom<IAllowAnonymous>(endpoint.Metadata.GetMetadata<IAllowAnonymous>());
    }

    [Fact]
    public void AuthenticationMetadata_DeclaresTokenFreeTwoFactorContinuation() {
        using var host = CreateHost(includeVerificationDependencies: false);
        host.Endpoints.MapAuthenticationApi<IdentityUser<int>, TestUserDto, int>();

        var login = Assert.Single(Endpoints(host).OfType<RouteEndpoint>());
        var accepted = Assert.Single(login.Metadata.GetOrderedMetadata<Microsoft.AspNetCore.Http.Metadata.IProducesResponseTypeMetadata>()
            .Where(metadata => metadata.StatusCode == StatusCodes.Status202Accepted));
        Assert.Equal(typeof(AuthenticationContinuationResponse), accepted.Type);
        Assert.DoesNotContain(typeof(RuntimeApps.Authentication.Shared.Models.Token).Name, accepted.Type!.GetProperties().Select(property => property.Name));
    }

    [Fact]
    public void ExternalLoginMetadata_DeclaresSanitized401AndMalformedRequest400() {
        using var host = CreateHost(includeVerificationDependencies: false, includeExternalProvider: true);
        host.Endpoints.MapAuthenticationApi<IdentityUser<int>, TestUserDto, int>();

        var externalLogin = Assert.Single(Endpoints(host).OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.RoutePattern.RawText?.Contains("external", StringComparison.OrdinalIgnoreCase) == true));
        var responses = externalLogin.Metadata.GetOrderedMetadata<Microsoft.AspNetCore.Http.Metadata.IProducesResponseTypeMetadata>();
        Assert.Contains(responses, response => response.StatusCode == StatusCodes.Status400BadRequest && response.Type == typeof(HttpValidationProblemDetails));
        Assert.Contains(responses, response => response.StatusCode == StatusCodes.Status401Unauthorized && response.Type == typeof(Microsoft.AspNetCore.Mvc.ProblemDetails));
    }

    [Fact]
    public async Task ExternalLogin_MalformedBodyReturns400AndProviderFailureReturnsSanitized401() {
        using var host = CreateHost(includeVerificationDependencies: false, includeExternalProvider: true);
        host.Endpoints.MapAuthenticationApi<IdentityUser<int>, TestUserDto, int>();
        var externalLogin = Endpoints(host).OfType<RouteEndpoint>()
            .Single(endpoint => endpoint.RoutePattern.RawText?.Contains("external", StringComparison.OrdinalIgnoreCase) == true);
        var account = Mock.Get(host.Endpoints.ServiceProvider.GetRequiredService<IUserAccountService<IdentityUser<int>>>());
        account.Setup(service => service.ExternalLoginAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RuntimeApps.Authentication.Shared.Models.Result<IdentityUser<int>, RuntimeApps.Authentication.Shared.Models.Token>(
                RuntimeApps.Authentication.Shared.Models.ResultCode.BadRequest,
                RuntimeApps.Authentication.Shared.Models.Result.CreateErrors("ProviderFailure", "private provider detail")));

        static async Task<(int Status, string Body)> Send(RouteEndpoint endpoint, IServiceProvider services, string json) {
            var context = new DefaultHttpContext();
            context.RequestServices = services;
            context.Request.Method = "POST";
            context.Request.ContentType = "application/json";
            var bytes = Encoding.UTF8.GetBytes(json);
            context.Request.Body = new MemoryStream(bytes);
            context.Request.ContentLength = bytes.Length;
            context.Features.Set<IHttpRequestBodyDetectionFeature>(new TestBodyDetectionFeature());
            await using var response = new MemoryStream();
            context.Response.Body = response;
            await endpoint.RequestDelegate!(context);
            response.Position = 0;
            return (context.Response.StatusCode, await new StreamReader(response).ReadToEndAsync());
        }

        var malformed = await Send(externalLogin, host.Endpoints.ServiceProvider, "{\"Provider\":\"\",\"Token\":\"x\"}");
        Assert.Equal(StatusCodes.Status400BadRequest, malformed.Status);
        Assert.Contains("InvalidExternalLogin", malformed.Body);
        Assert.DoesNotContain("private provider detail", malformed.Body);

        var rejected = await Send(externalLogin, host.Endpoints.ServiceProvider, "{\"Provider\":\"sample\",\"Token\":\"invalid\"}");
        Assert.True(rejected.Status == StatusCodes.Status401Unauthorized, $"Expected 401, got {rejected.Status}: {rejected.Body}");
        Assert.Contains("External authentication could not be completed.", rejected.Body);
        Assert.DoesNotContain("private provider detail", rejected.Body);
        Assert.DoesNotContain("ProviderFailure", rejected.Body);
    }

    [Fact]
    public async Task Login_TwoFactorRequired_Returns202WithChallengeAndNoToken() {
        using var host = CreateHost(includeVerificationDependencies: false);
        host.Endpoints.MapAuthenticationApi<IdentityUser<int>, TestUserDto, int>();
        var login = Endpoints(host).OfType<RouteEndpoint>().Single();
        var expires = new DateTimeOffset(2026, 1, 1, 9, 5, 0, TimeSpan.Zero);
        Mock.Get(host.Endpoints.ServiceProvider.GetRequiredService<IUserAccountService<IdentityUser<int>>>())
            .Setup(service => service.LoginAsync("alice", "password", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<IdentityUser<int>, Token>(ResultCode.Accepted, Result.CreateErrors("TwoFactorRequired", "A second authentication step is required.")) {
                // A token in Meta must never reach the response, even by mistake.
                Meta = new Token {
                    AuthenticationToken = "must-not-leak",
                    TwoFactorChallenge = "handle-1",
                    TwoFactorExpiresAt = expires,
                    TwoFactorMethods = [new TwoFactorMethodInfo("authenticator", false), new TwoFactorMethodInfo("sms", true)]
                }
            });

        var response = await SendJson(login, host.Endpoints.ServiceProvider, "{\"UserName\":\"alice\",\"Password\":\"password\"}");

        Assert.Equal(StatusCodes.Status202Accepted, response.Status);
        using var json = System.Text.Json.JsonDocument.Parse(response.Body);
        var root = json.RootElement;
        Assert.True(root.GetProperty("requiresTwoFactor").GetBoolean());
        Assert.Equal("handle-1", root.GetProperty("twoFactorChallenge").GetString());
        Assert.Equal(expires, root.GetProperty("expiresAt").GetDateTimeOffset());
        var methods = root.GetProperty("methods").EnumerateArray().ToArray();
        Assert.Equal(2, methods.Length);
        Assert.Equal("authenticator", methods[0].GetProperty("name").GetString());
        Assert.False(methods[0].GetProperty("requiresSend").GetBoolean());
        Assert.True(methods[1].GetProperty("requiresSend").GetBoolean());
        Assert.DoesNotContain("must-not-leak", response.Body);
        Assert.DoesNotContain("authenticationToken", response.Body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Login_TwoFactorRequired_WithoutTwoFactorFeature_KeepsTheOriginalBody() {
        using var host = CreateHost(includeVerificationDependencies: false);
        host.Endpoints.MapAuthenticationApi<IdentityUser<int>, TestUserDto, int>();
        var login = Endpoints(host).OfType<RouteEndpoint>().Single();
        Mock.Get(host.Endpoints.ServiceProvider.GetRequiredService<IUserAccountService<IdentityUser<int>>>())
            .Setup(service => service.LoginAsync("alice", "password", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<IdentityUser<int>, Token>(ResultCode.Accepted, Result.CreateErrors("TwoFactorRequired", "A second authentication step is required.")));

        var response = await SendJson(login, host.Endpoints.ServiceProvider, "{\"UserName\":\"alice\",\"Password\":\"password\"}");

        Assert.Equal(StatusCodes.Status202Accepted, response.Status);
        Assert.Equal("{\"requiresTwoFactor\":true}", response.Body);
    }

    [Fact]
    public async Task Login_EmptyChallengeInMeta_IsTreatedAsNoChallenge() {
        using var host = CreateHost(includeVerificationDependencies: false);
        host.Endpoints.MapAuthenticationApi<IdentityUser<int>, TestUserDto, int>();
        var login = Endpoints(host).OfType<RouteEndpoint>().Single();
        Mock.Get(host.Endpoints.ServiceProvider.GetRequiredService<IUserAccountService<IdentityUser<int>>>())
            .Setup(service => service.LoginAsync("alice", "password", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<IdentityUser<int>, Token>(ResultCode.Accepted, Result.CreateErrors("TwoFactorRequired", "x")) {
                Meta = new Token { TwoFactorChallenge = "" }
            });

        var response = await SendJson(login, host.Endpoints.ServiceProvider, "{\"UserName\":\"alice\",\"Password\":\"password\"}");

        Assert.Equal("{\"requiresTwoFactor\":true}", response.Body);
    }

    private static RouteEndpoint MapTwoFactor(TestHost host) {
        host.Endpoints.MapAuthenticationApi<IdentityUser<int>, TestUserDto, int>();
        return Endpoints(host).OfType<RouteEndpoint>().Single(e => e.RoutePattern.RawText == "login/two-factor");
    }

    private static Mock<ITwoFactorLoginService<IdentityUser<int>>> TwoFactorService(TestHost host) =>
        Mock.Get(host.Endpoints.ServiceProvider.GetRequiredService<ITwoFactorLoginService<IdentityUser<int>>>());

    private const string TwoFactorBody = "{\"Challenge\":\"handle\",\"Method\":\"authenticator\",\"Code\":\"123456\"}";

    [Fact]
    public void TwoFactorLogin_IsNotMappedWithoutTheFeature() {
        using var host = CreateHost(includeVerificationDependencies: false);
        host.Endpoints.MapAuthenticationApi<IdentityUser<int>, TestUserDto, int>();

        Assert.DoesNotContain(Endpoints(host).OfType<RouteEndpoint>(), e => e.RoutePattern.RawText == "login/two-factor");
    }

    [Fact]
    public void TwoFactorLogin_IsMappedAnonymouslyAndDeclaresItsResponses() {
        using var host = CreateHost(includeVerificationDependencies: false, includeTwoFactor: true);

        var endpoint = MapTwoFactor(host);

        Assert.NotNull(endpoint.Metadata.GetMetadata<IAllowAnonymous>());
        var codes = endpoint.Metadata.GetOrderedMetadata<Microsoft.AspNetCore.Http.Metadata.IProducesResponseTypeMetadata>().Select(m => m.StatusCode).ToArray();
        Assert.Contains(StatusCodes.Status200OK, codes);
        Assert.Contains(StatusCodes.Status400BadRequest, codes);
        Assert.Contains(StatusCodes.Status401Unauthorized, codes);
        Assert.Contains(StatusCodes.Status429TooManyRequests, codes);
    }

    [Fact]
    public async Task TwoFactorLogin_ValidCode_Returns200WithToken() {
        using var host = CreateHost(includeVerificationDependencies: false, includeTwoFactor: true);
        var endpoint = MapTwoFactor(host);
        var service = TwoFactorService(host);
        service.Setup(s => s.CompleteAsync("handle", "authenticator", "123456", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<IdentityUser<int>, Token>(new IdentityUser<int> { Id = 1 }, new Token { AuthenticationToken = "access-token" }));

        var response = await SendJson(endpoint, host.Endpoints.ServiceProvider, TwoFactorBody);

        Assert.Equal(StatusCodes.Status200OK, response.Status);
        Assert.Contains("access-token", response.Body);
    }

    [Theory]
    [InlineData("{\"Challenge\":\"\",\"Method\":\"authenticator\",\"Code\":\"123456\"}")]
    [InlineData("{\"Challenge\":\"handle\",\"Method\":\" \",\"Code\":\"123456\"}")]
    [InlineData("{\"Challenge\":\"handle\",\"Method\":\"authenticator\"}")]
    public async Task TwoFactorLogin_MissingField_Returns400WithoutCallingTheService(string body) {
        using var host = CreateHost(includeVerificationDependencies: false, includeTwoFactor: true);
        var endpoint = MapTwoFactor(host);
        var service = TwoFactorService(host);

        var response = await SendJson(endpoint, host.Endpoints.ServiceProvider, body);

        Assert.Equal(StatusCodes.Status400BadRequest, response.Status);
        Assert.Contains("InvalidTwoFactorLogin", response.Body);
        service.Verify(s => s.CompleteAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Theory]
    [InlineData(ResultCode.BadRequest)]
    [InlineData(ResultCode.Forbidden)]
    [InlineData(ResultCode.Locked)]
    [InlineData(ResultCode.Conflict)]
    public async Task TwoFactorLogin_AnyFailure_Returns_TheSameSanitized401(ResultCode code) {
        using var host = CreateHost(includeVerificationDependencies: false, includeTwoFactor: true);
        var endpoint = MapTwoFactor(host);
        TwoFactorService(host).Setup(s => s.CompleteAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<IdentityUser<int>, Token>(code, Result.CreateErrors("PrivateReason", "private internal detail")));

        var response = await SendJson(endpoint, host.Endpoints.ServiceProvider, TwoFactorBody);

        Assert.Equal(StatusCodes.Status401Unauthorized, response.Status);
        using var json = System.Text.Json.JsonDocument.Parse(response.Body);
        Assert.Equal("authentication_failed", json.RootElement.GetProperty("code").GetString());
        Assert.Equal("The code is incorrect or the sign-in attempt has expired.", json.RootElement.GetProperty("detail").GetString());
        Assert.DoesNotContain("PrivateReason", response.Body);
        Assert.DoesNotContain("private internal detail", response.Body);
        Assert.DoesNotContain("handle", response.Body);
        Assert.DoesNotContain("123456", response.Body);
    }

    [Fact]
    public async Task TwoFactorLogin_WhenThrottled_Returns429BeforeAnyWork() {
        using var host = CreateHost(includeVerificationDependencies: false, includeTwoFactor: true);
        var endpoint = MapTwoFactor(host);
        var service = TwoFactorService(host);
        Mock.Get(host.Endpoints.ServiceProvider.GetRequiredService<ITwoFactorRequestLimiter>())
            .Setup(l => l.IsAllowedAsync(It.IsAny<HttpContext>(), It.IsAny<CancellationToken>())).Returns(new ValueTask<bool>(false));

        var response = await SendJson(endpoint, host.Endpoints.ServiceProvider, TwoFactorBody);

        Assert.Equal(StatusCodes.Status429TooManyRequests, response.Status);
        service.Verify(s => s.CompleteAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task TwoFactorLogin_ThrottleAppliesEvenToMalformedRequests() {
        using var host = CreateHost(includeVerificationDependencies: false, includeTwoFactor: true);
        var endpoint = MapTwoFactor(host);
        Mock.Get(host.Endpoints.ServiceProvider.GetRequiredService<ITwoFactorRequestLimiter>())
            .Setup(l => l.IsAllowedAsync(It.IsAny<HttpContext>(), It.IsAny<CancellationToken>())).Returns(new ValueTask<bool>(false));

        var response = await SendJson(endpoint, host.Endpoints.ServiceProvider, "{\"Challenge\":\"\"}");

        Assert.Equal(StatusCodes.Status429TooManyRequests, response.Status);
    }

    [Fact]
    public void RegistrationMapping_IsIndependentAndAnonymous() {
        using var host = CreateHost(includeVerificationDependencies: true);

        host.Endpoints.MapGroup("api/register")
            .MapRegistrationApi<IdentityUser<int>, TestUserDto, int>();

        var endpoint = Assert.Single(Endpoints(host));
        Assert.Equal("api/register/register", ((RouteEndpoint)endpoint).RoutePattern.RawText);
        Assert.IsAssignableFrom<IAllowAnonymous>(endpoint.Metadata.GetMetadata<IAllowAnonymous>());
        Assert.Equal("Registration_Register", endpoint.Metadata.GetMetadata<IEndpointNameMetadata>()?.EndpointName);
        var accepted = Assert.Single(endpoint.Metadata.GetOrderedMetadata<Microsoft.AspNetCore.Http.Metadata.IProducesResponseTypeMetadata>()
            .Where(metadata => metadata.StatusCode == StatusCodes.Status202Accepted));
        Assert.Equal(typeof(RuntimeApps.Authentication.Shared.Models.Result<RuntimeApps.Authentication.Features.Registration.Models.RegistrationVerificationResponse>), accepted.Type);
    }

    [Fact]
    public void VerificationMapping_UsesTheChosenDtoAndMapsOnlyVerificationRoutes() {
        using var host = CreateHost(includeVerificationDependencies: true);

        host.Endpoints.MapGroup("api/register")
            .MapVerificationApi<IdentityUser<int>, TestUserDto, int>();

        var endpoints = Endpoints(host).OfType<RouteEndpoint>().ToArray();
        Assert.Equal(new[] { "api/register/register/resend", "api/register/register/verify" },
            endpoints.Select(endpoint => endpoint.RoutePattern.RawText).OrderBy(route => route, StringComparer.Ordinal));
        Assert.All(endpoints, endpoint => Assert.IsAssignableFrom<IAllowAnonymous>(endpoint.Metadata.GetMetadata<IAllowAnonymous>()));
        Assert.Equal(2, endpoints.Select(endpoint => endpoint.Metadata.GetMetadata<IEndpointNameMetadata>()?.EndpointName).Distinct().Count());
    }

    [Fact]
    public void RegistrationMapping_ReportsMissingDependenciesAtMappingTime() {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IRegistrationService<IdentityUser<int>, int>>());
        services.AddSingleton(Mock.Of<IUserAccountService<IdentityUser<int>>>());
        services.AddSingleton(Mock.Of<IUserMapper<IdentityUser<int>, TestUserDto>>());
        using var host = new TestHost(services.BuildServiceProvider());

        var error = Assert.Throws<InvalidOperationException>(() => host.Endpoints
            .MapRegistrationApi<IdentityUser<int>, TestUserDto, int>());

        Assert.Contains("Registration", error.Message, StringComparison.Ordinal);
        Assert.Contains("IVerificationWorkflowService", error.Message, StringComparison.Ordinal);
        Assert.Contains("IVerificationRequestStore", error.Message, StringComparison.Ordinal);
        Assert.Contains("IVerificationSender", error.Message, StringComparison.Ordinal);
    }

    private static async Task<(int Status, string Body)> SendJson(RouteEndpoint endpoint, IServiceProvider services, string json, Action<HttpContext> configure = null) {
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Method = "POST";
        context.Request.ContentType = "application/json";
        var bytes = Encoding.UTF8.GetBytes(json);
        context.Request.Body = new MemoryStream(bytes);
        context.Request.ContentLength = bytes.Length;
        context.Features.Set<IHttpRequestBodyDetectionFeature>(new TestBodyDetectionFeature());
        configure?.Invoke(context);
        await using var response = new MemoryStream();
        context.Response.Body = response;
        await endpoint.RequestDelegate!(context);
        response.Position = 0;
        return (context.Response.StatusCode, await new StreamReader(response).ReadToEndAsync());
    }

    private static TestHost CreateHost(bool includeVerificationDependencies, bool includeExternalProvider = false, bool includeTwoFactor = false) {
        var services = new ServiceCollection();
        services.AddLogging().AddProblemDetails();
        services.AddSingleton(Mock.Of<IRegistrationService<IdentityUser<int>, int>>());
        services.AddSingleton(Mock.Of<IUserAccountService<IdentityUser<int>>>());
        services.AddSingleton(Mock.Of<IUserMapper<IdentityUser<int>, TestUserDto>>());
        if(includeExternalProvider)
            services.AddSingleton<IExternalLoginProvider<IdentityUser<int>>>(Mock.Of<IExternalLoginProvider<IdentityUser<int>>>());
        if(includeTwoFactor) {
            services.AddSingleton(Mock.Of<ITwoFactorLoginService<IdentityUser<int>>>());
            var limiter = new Mock<ITwoFactorRequestLimiter>();
            limiter.Setup(l => l.IsAllowedAsync(It.IsAny<HttpContext>(), It.IsAny<CancellationToken>())).Returns(new ValueTask<bool>(true));
            services.AddSingleton(limiter);
            services.AddSingleton(limiter.Object);
        }
        if(includeVerificationDependencies) {
            services.AddSingleton(Mock.Of<IVerificationWorkflowService<IdentityUser<int>, int>>());
            services.AddSingleton(Mock.Of<IVerificationRequestStore<int>>());
            services.AddSingleton(Mock.Of<IVerificationSender<IdentityUser<int>, int>>());
        }
        var provider = services.BuildServiceProvider();
        return new TestHost(includeExternalProvider ? new TestServiceProvider(provider) : provider);
    }

    private static Endpoint[] Endpoints(TestHost host) => host.Endpoints.DataSources
        .SelectMany(source => source.Endpoints).ToArray();

    public sealed class TestUserDto { }

    private sealed class TestServiceProvider(IServiceProvider inner) : IServiceProvider, IServiceProviderIsService {
        public object GetService(Type serviceType) => serviceType == typeof(IServiceProviderIsService) ? this : inner.GetService(serviceType);
        public bool IsService(Type serviceType) => serviceType == typeof(IExternalLoginProvider<IdentityUser<int>>) ||
            inner.GetService<IServiceProviderIsService>()?.IsService(serviceType) == true;
    }

    private sealed class TestBodyDetectionFeature : IHttpRequestBodyDetectionFeature {
        public bool CanHaveBody => true;
    }

    private sealed class TestHost : IDisposable {
        public TestHost(IServiceProvider services) => Endpoints = new TestEndpointRouteBuilder(services);
        public TestEndpointRouteBuilder Endpoints { get; }
        public void Dispose() => (Endpoints.ServiceProvider as IDisposable)?.Dispose();
    }

    private sealed class TestEndpointRouteBuilder : IEndpointRouteBuilder {
        public TestEndpointRouteBuilder(IServiceProvider services) => ServiceProvider = services;
        public ICollection<EndpointDataSource> DataSources { get; } = new List<EndpointDataSource>();
        public IServiceProvider ServiceProvider { get; }
        public IApplicationBuilder CreateApplicationBuilder() => new ApplicationBuilder(ServiceProvider);
    }
}
