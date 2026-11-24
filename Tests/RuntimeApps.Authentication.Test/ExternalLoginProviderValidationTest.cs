using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
using RuntimeApps.Authentication.Features.ExternalLogin.Providers;
namespace RuntimeApps.Authentication.Test {
    /// <summary>
    /// Provider-level validation matrix: invalid signature, issuer/audience mismatch, expiry, unverified
    /// email and missing subject. Microsoft is exercised with real JWT validation against a stubbed
    /// metadata endpoint. Facebook is exercised against stubbed Graph API responses. Google's signature,
    /// issuer, expiry and audience checks live in Google.Apis.Auth, which needs Google's certificate
    /// endpoint, so those tests simulate the library rejecting a token and verify how the provider
    /// reacts and which audience it asks the library to enforce.
    /// </summary>
    public class ExternalLoginProviderValidationTest {
        // ---------- Google ----------

        private sealed class TestableGoogleProvider: GoogleExternalLoginProvider<IdentityUser> {
            private readonly Func<string, string, GoogleJsonWebSignature.Payload> _validate;

            public TestableGoogleProvider(GoogleExternalLoginOption<IdentityUser> option,
                                          Func<string, string, GoogleJsonWebSignature.Payload> validate)
                : base(Microsoft.Extensions.Options.Options.Create(option), NullLogger<GoogleExternalLoginProvider<IdentityUser>>.Instance) {
                _validate = validate;
            }

            public int ValidationCalls { get; private set; }
            public string RequestedAudience { get; private set; }

            protected override Task<GoogleJsonWebSignature.Payload> ValidatePayloadAsync(
                string token, string audience, CancellationToken cancellationToken) {
                ValidationCalls++;
                RequestedAudience = audience;
                return Task.FromResult(_validate(token, audience));
            }
        }

        private static GoogleExternalLoginOption<IdentityUser> GoogleOption(string clientId = "google-client") =>
            new GoogleExternalLoginOption<IdentityUser> {
                ClientId = clientId,
                ClientSecret = "secret",
                Mapper = payload => new IdentityUser { Email = payload.Email, UserName = payload.Email }
            };

        [Fact]
        public async Task Google_ValidToken_ReturnsStableSubjectAndAsksLibraryToEnforceConfiguredAudience() {
            var provider = new TestableGoogleProvider(GoogleOption(), (token, audience) => new GoogleJsonWebSignature.Payload {
                Subject = "google-subject-1",
                Email = "person@gmail.com",
                EmailVerified = true
            });

            var result = await provider.ValidateAsync("id-token");

            Assert.NotNull(result);
            Assert.Equal("GOOGLE", result.LoginInfo.LoginProvider);
            Assert.Equal("google-subject-1", result.LoginInfo.ProviderKey);
            Assert.Equal("person@gmail.com", result.Email);
            Assert.True(result.EmailVerified);
            Assert.Equal("google-client", provider.RequestedAudience);
        }

        [Theory]
        [InlineData("Invalid signature.")]
        [InlineData("Issuer is not accounts.google.com.")]
        [InlineData("Audience does not match the configured client ID.")]
        [InlineData("JWT has expired.")]
        public async Task Google_TokenRejectedByLibrary_ReturnsNull(string reason) {
            var provider = new TestableGoogleProvider(GoogleOption(),
                (token, audience) => throw new InvalidJwtException(reason));

            var result = await provider.ValidateAsync("id-token");

            Assert.Null(result);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task Google_MissingSubject_ReturnsNull(string subject) {
            var provider = new TestableGoogleProvider(GoogleOption(), (token, audience) => new GoogleJsonWebSignature.Payload {
                Subject = subject,
                Email = "person@gmail.com",
                EmailVerified = true
            });

            var result = await provider.ValidateAsync("id-token");

            Assert.Null(result);
        }

        [Fact]
        public async Task Google_UnverifiedEmail_IsReportedAsUnverified() {
            var provider = new TestableGoogleProvider(GoogleOption(), (token, audience) => new GoogleJsonWebSignature.Payload {
                Subject = "google-subject-1",
                Email = "person@gmail.com",
                EmailVerified = false
            });

            var result = await provider.ValidateAsync("id-token");

            Assert.NotNull(result);
            Assert.False(result.EmailVerified);
        }

        [Theory]
        [InlineData("", "google-client")]
        [InlineData("   ", "google-client")]
        [InlineData("id-token", "")]
        [InlineData("id-token", "   ")]
        public async Task Google_MissingTokenOrClientId_ReturnsNullWithoutValidating(string token, string clientId) {
            var provider = new TestableGoogleProvider(GoogleOption(clientId),
                (t, audience) => new GoogleJsonWebSignature.Payload { Subject = "google-subject-1" });

            var result = await provider.ValidateAsync(token);

            Assert.Null(result);
            Assert.Equal(0, provider.ValidationCalls);
        }

        [Fact]
        public async Task Google_MapperReturnsNull_ReturnsNull() {
            var option = GoogleOption();
            option.Mapper = payload => null;
            var provider = new TestableGoogleProvider(option,
                (token, audience) => new GoogleJsonWebSignature.Payload { Subject = "google-subject-1" });

            var result = await provider.ValidateAsync("id-token");

            Assert.Null(result);
        }

        [Fact]
        public async Task Google_CancellationRequested_IsNotSwallowed() {
            var provider = new TestableGoogleProvider(GoogleOption(),
                (token, audience) => new GoogleJsonWebSignature.Payload { Subject = "google-subject-1" });
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                provider.ValidateAsync("id-token", cancellation.Token));
            Assert.Equal(0, provider.ValidationCalls);
        }

        // ---------- Stubbed HTTP ----------

        private sealed class StubHandler: HttpMessageHandler {
            private readonly List<(string Prefix, string Body)> _routes = new List<(string, string)>();

            public List<string> RequestedUrls { get; } = new List<string>();

            public StubHandler Route(string prefix, string body) {
                _routes.Add((prefix, body));
                return this;
            }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
                var url = request.RequestUri.ToString();
                RequestedUrls.Add(url);
                foreach(var (prefix, body) in _routes) {
                    if(url.StartsWith(prefix, StringComparison.Ordinal))
                        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
                            Content = new StringContent(body, Encoding.UTF8, "application/json")
                        });
                }
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }
        }

        private static IHttpClientFactory FactoryFor(StubHandler handler) {
            var factory = new Mock<IHttpClientFactory>();
            // Providers dispose the client they create, so every call gets a new client over the shared handler.
            factory.Setup(item => item.CreateClient(It.IsAny<string>()))
                .Returns(() => new HttpClient(handler, disposeHandler: false));
            return factory.Object;
        }

        // ---------- Microsoft ----------

        private const string MicrosoftClientId = "ms-client";
        private const string MicrosoftTenant = "11111111-1111-1111-1111-111111111111";
        private const string MicrosoftObjectId = "22222222-2222-2222-2222-222222222222";
        private const string MicrosoftKeyId = "test-key";
        private const string MetadataUrl = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";
        private const string JwksUrl = "https://login.microsoftonline.com/common/discovery/v2.0/keys";

        private static string IssuerFor(string tenant) => $"https://login.microsoftonline.com/{tenant}/v2.0";

        private static StubHandler MicrosoftMetadata(RSA signingKey) {
            var parameters = signingKey.ExportParameters(false);
            var jwks = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"" + MicrosoftKeyId +
                       "\",\"n\":\"" + Base64UrlEncoder.Encode(parameters.Modulus) +
                       "\",\"e\":\"" + Base64UrlEncoder.Encode(parameters.Exponent) + "\"}]}";
            var configuration = "{\"issuer\":\"https://login.microsoftonline.com/{tenantid}/v2.0\"," +
                                "\"jwks_uri\":\"" + JwksUrl + "\"," +
                                "\"id_token_signing_alg_values_supported\":[\"RS256\"]}";
            return new StubHandler().Route(MetadataUrl, configuration).Route(JwksUrl, jwks);
        }

        private static string MicrosoftToken(RSA signingKey,
                                             string issuer = null,
                                             string audience = MicrosoftClientId,
                                             string tenant = MicrosoftTenant,
                                             string objectId = MicrosoftObjectId,
                                             DateTime? notBefore = null,
                                             DateTime? expires = null) {
            var claims = new List<Claim> { new Claim("email", "person@contoso.com") };
            if(tenant != null)
                claims.Add(new Claim("tid", tenant));
            if(objectId != null)
                claims.Add(new Claim("oid", objectId));

            var credentials = new SigningCredentials(
                new RsaSecurityKey(signingKey) { KeyId = MicrosoftKeyId }, SecurityAlgorithms.RsaSha256);
            var token = new JwtSecurityToken(
                issuer ?? IssuerFor(tenant ?? MicrosoftTenant), audience, claims,
                notBefore ?? DateTime.UtcNow.AddMinutes(-5), expires ?? DateTime.UtcNow.AddMinutes(55), credentials);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private static MicrosoftExternalLoginProvider<IdentityUser> MicrosoftProvider(StubHandler handler) =>
            new MicrosoftExternalLoginProvider<IdentityUser>(
                Microsoft.Extensions.Options.Options.Create(new MicrosoftExternalLoginOption<IdentityUser> {
                    ClientId = MicrosoftClientId,
                    ClientSecret = "secret",
                    Mapper = jwt => new IdentityUser { Email = jwt.Claims.FirstOrDefault(claim => claim.Type == "email")?.Value }
                }),
                FactoryFor(handler),
                NullLogger<MicrosoftExternalLoginProvider<IdentityUser>>.Instance);

        [Fact]
        public async Task Microsoft_ValidToken_ReturnsTenantScopedSubjectAndUnverifiedEmail() {
            using var key = RSA.Create(2048);
            var provider = MicrosoftProvider(MicrosoftMetadata(key));

            var result = await provider.ValidateAsync(MicrosoftToken(key));

            Assert.NotNull(result);
            Assert.Equal("MICROSOFT", result.LoginInfo.LoginProvider);
            Assert.Equal($"{MicrosoftTenant}:{MicrosoftObjectId}", result.LoginInfo.ProviderKey);
            Assert.Equal("person@contoso.com", result.Email);
            Assert.False(result.EmailVerified);
        }

        [Fact]
        public async Task Microsoft_InvalidSignature_ReturnsNull() {
            using var trustedKey = RSA.Create(2048);
            using var attackerKey = RSA.Create(2048);
            var provider = MicrosoftProvider(MicrosoftMetadata(trustedKey));

            var result = await provider.ValidateAsync(MicrosoftToken(attackerKey));

            Assert.Null(result);
        }

        [Fact]
        public async Task Microsoft_IssuerDoesNotMatchTenantClaim_ReturnsNull() {
            using var key = RSA.Create(2048);
            var provider = MicrosoftProvider(MicrosoftMetadata(key));
            var token = MicrosoftToken(key, issuer: IssuerFor("33333333-3333-3333-3333-333333333333"));

            var result = await provider.ValidateAsync(token);

            Assert.Null(result);
        }

        [Fact]
        public async Task Microsoft_AudienceMismatch_ReturnsNull() {
            using var key = RSA.Create(2048);
            var provider = MicrosoftProvider(MicrosoftMetadata(key));

            var result = await provider.ValidateAsync(MicrosoftToken(key, audience: "another-application"));

            Assert.Null(result);
        }

        [Fact]
        public async Task Microsoft_ExpiredToken_ReturnsNull() {
            using var key = RSA.Create(2048);
            var provider = MicrosoftProvider(MicrosoftMetadata(key));
            var token = MicrosoftToken(key, notBefore: DateTime.UtcNow.AddHours(-2), expires: DateTime.UtcNow.AddHours(-1));

            var result = await provider.ValidateAsync(token);

            Assert.Null(result);
        }

        [Fact]
        public async Task Microsoft_MissingObjectId_ReturnsNull() {
            using var key = RSA.Create(2048);
            var provider = MicrosoftProvider(MicrosoftMetadata(key));

            var result = await provider.ValidateAsync(MicrosoftToken(key, objectId: null));

            Assert.Null(result);
        }

        [Fact]
        public async Task Microsoft_MissingTenantId_ReturnsNull() {
            using var key = RSA.Create(2048);
            var provider = MicrosoftProvider(MicrosoftMetadata(key));

            var result = await provider.ValidateAsync(MicrosoftToken(key, tenant: null));

            Assert.Null(result);
        }

        [Fact]
        public async Task Microsoft_MetadataUnavailable_ReturnsNull() {
            using var key = RSA.Create(2048);
            var provider = MicrosoftProvider(new StubHandler());

            var result = await provider.ValidateAsync(MicrosoftToken(key));

            Assert.Null(result);
        }

        // ---------- Facebook ----------

        private const long FacebookAppId = 42;
        private const long FacebookUserId = 123;

        private static StubHandler FacebookGraph(string debugTokenBody, string meBody) =>
            new StubHandler()
                .Route("https://graph.facebook.com/oauth/access_token?", "{\"access_token\":\"app-token\",\"token_type\":\"bearer\"}")
                .Route("https://graph.facebook.com/debug_token?", debugTokenBody)
                .Route("https://graph.facebook.com/v27.0/me?", meBody);

        private static string DebugBody(long appId = FacebookAppId, long? userId = FacebookUserId, bool isValid = true, long expiresAt = 0) =>
            "{\"data\":{\"app_id\":" + appId + ",\"is_valid\":" + (isValid ? "true" : "false") +
            ",\"expires_at\":" + expiresAt +
            (userId.HasValue ? ",\"user_id\":" + userId.Value : string.Empty) + "}}";

        private static string MeBody(long? id = FacebookUserId, string email = "person@example.com") =>
            "{" + (id.HasValue ? "\"id\":" + id.Value + "," : string.Empty) + "\"email\":\"" + email + "\",\"name\":\"Person\"}";

        private static FacebookExternalLoginProvider<IdentityUser> FacebookProvider(StubHandler handler, string clientId = "42") =>
            new FacebookExternalLoginProvider<IdentityUser>(
                Microsoft.Extensions.Options.Options.Create(new FacebookExternalLoginOption<IdentityUser> {
                    ClientId = clientId,
                    ClientSecret = "secret",
                    Mapper = data => new IdentityUser { Email = data.Email }
                }),
                FactoryFor(handler),
                NullLogger<FacebookExternalLoginProvider<IdentityUser>>.Instance);

        [Fact]
        public async Task Facebook_ValidToken_ReturnsSubjectAndUnverifiedEmail() {
            var future = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
            var provider = FacebookProvider(FacebookGraph(DebugBody(expiresAt: future), MeBody()));

            var result = await provider.ValidateAsync("user-access-token");

            Assert.NotNull(result);
            Assert.Equal("FACEBOOK", result.LoginInfo.LoginProvider);
            Assert.Equal("123", result.LoginInfo.ProviderKey);
            Assert.Equal("person@example.com", result.Email);
            Assert.False(result.EmailVerified);
        }

        [Fact]
        public async Task Facebook_InvalidToken_ReturnsNull() {
            var provider = FacebookProvider(FacebookGraph(DebugBody(isValid: false), MeBody()));

            var result = await provider.ValidateAsync("user-access-token");

            Assert.Null(result);
        }

        [Fact]
        public async Task Facebook_TokenIssuedForAnotherApplication_ReturnsNull() {
            var provider = FacebookProvider(FacebookGraph(DebugBody(appId: 99), MeBody()));

            var result = await provider.ValidateAsync("user-access-token");

            Assert.Null(result);
        }

        [Fact]
        public async Task Facebook_ExpiredToken_ReturnsNull() {
            var past = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
            var provider = FacebookProvider(FacebookGraph(DebugBody(expiresAt: past), MeBody()));

            var result = await provider.ValidateAsync("user-access-token");

            Assert.Null(result);
        }

        [Fact]
        public async Task Facebook_MissingSubjectInTokenInspection_ReturnsNull() {
            var provider = FacebookProvider(FacebookGraph(DebugBody(userId: null), MeBody()));

            var result = await provider.ValidateAsync("user-access-token");

            Assert.Null(result);
        }

        [Fact]
        public async Task Facebook_MissingSubjectInProfile_ReturnsNull() {
            var provider = FacebookProvider(FacebookGraph(DebugBody(), MeBody(id: null)));

            var result = await provider.ValidateAsync("user-access-token");

            Assert.Null(result);
        }

        [Fact]
        public async Task Facebook_ProfileSubjectDiffersFromInspectedToken_ReturnsNull() {
            var provider = FacebookProvider(FacebookGraph(DebugBody(userId: 123), MeBody(id: 124)));

            var result = await provider.ValidateAsync("user-access-token");

            Assert.Null(result);
        }

        [Theory]
        [InlineData("not-a-number")]
        [InlineData("")]
        [InlineData("-42")]
        public async Task Facebook_InvalidConfiguredAppId_ReturnsNullWithoutCallingFacebook(string clientId) {
            var handler = FacebookGraph(DebugBody(), MeBody());
            var provider = FacebookProvider(handler, clientId);

            var result = await provider.ValidateAsync("user-access-token");

            Assert.Null(result);
            Assert.Empty(handler.RequestedUrls);
        }
    }
}
