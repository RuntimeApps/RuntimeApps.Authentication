# RuntimeApps.Authentication

The UserManager of ASP.Net core is good for most of the porposes and it implements in various types of [Databases](https://github.com/dotnet/aspnetcore/tree/main/src/Identity#community-maintained-store-providers).

But there are some problems with this implementation. I list some of them that I have tried to improve it:

- The Identity server of ASP.Net core has used [Identity Server 4](https://github.com/IdentityServer/IdentityServer4) however it has been archived and moved to [Duende Software](https://github.com/duendesoftware) which is not free. But I believe in most cases software doesn't need an Identity Server and They want to have simple user management. So this repository only supports simple usage of user managers based on what might be useful for your project.
- The default implementation of ASP.Net core user manager has been dependent on MVC (implements razor pages). This repository focuses on Web API applications that have separate frontend and backend code. So you can easily use APIs on user managers and external logins.
- Some implementations of ASP.Net core user management should be improved. For example, `UserManager<TUser>` doesn't inherit any interfaces which makes it very hard to write tests. In this repository, I have tried to solve some of these problems.
- Asp.Net core external social logins works based on redirecting to the social login page which is not useful in ASP.Net core Web APIs. ASP.Net core implements this by using MVC and managing the request responses, But this repository has implemented social login token validation which is useful for APIs that don't access user pages (Mobile apps and frontend frameworks).

## Samples
There is lots of samples that show how to use ASP.Net core identity and this library. Duo to the fact that this library is using ASP.Net core identity, other samples of other projects is useful too. The samples that re provided are:

Sample | Description
--- | ----
[Basic](./Samples/RuntimeApps.Authentication.Sample/) | Basic sample that configure simple user manager with basic APIs and external logins.
[Custom Model](./Samples/RuntimeApps.Authentication.Sample.CustomModel/) | Sample with custom user and role model which gets data from user and external login.
[Custom Validation](./Samples/RuntimeApps.Authentication.Sample.CustomValidation/) | Sample of ASP.Net core identity which costomize validation.
[Custom Store](./Samples/RuntimeApps.Authentication.Sample.CustomStore/) | Sample of implementing identity stores
[Role Authorize](./Samples/RuntimeApps.Authentication.Sample.RoleAuthorize/) | Sample of user role management and authroization based on role-base authorization.
[Claim Authorize](./Samples/RuntimeApps.Authentication.Sample.ClaimAuthorize/) | Sample of managing roles and claims of user. Also, implementing a sample of claim-based authorization in ASP.Net core
[Cookie Authentication](./Samples/RuntimeApps.Authentication.Sample.CookieAuthentication/) | Sample of use cookie authentication for handling authentication and authorization.
[Custom claim](./Samples/RuntimeApps.Authentication.Sample.CustomClaim/) | Sample of add custom claim to jwt token and describe default implementation of claim factory.
Email Verification | Verify user email by sending an email to user for validation
Two step authentication | Enable two step authentication for some users
Protect personal data | Protect personal user data in database by encrypt user data

## Getting Started

To use this library do the steps:

### Install packages:

Install `RuntimeApps.Authentication` package which implements base services.

```Install-Package RuntimeApps.Authentication```

If you want to use EntityFrameworkCore implementation of Authentication install the package

```Install-Package RuntimeApps.Authentication.EF```

Or you can install other implementations of the store [link](https://github.com/dotnet/aspnetcore/tree/main/src/Identity#community-maintained-store-providers)

### Create needed classes

Create your own `ApplicationDbContext` and inherent `IdentityDbContext`

### Configure Services

Add required services to DI:

```cs
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
    .AddEfStores<ApplicationDbContext, IdentityUser, IdentityRole, string>()
    .UseJwt(JwtBearerDefaults.AuthenticationScheme, builder.Configuration, option => {
        var signingKey = builder.Configuration["Authentication:Jwt:SigningKey"]
            ?? throw new InvalidOperationException("Set Authentication:Jwt:SigningKey in user secrets or an environment variable.");
        option.TokenValidationParameters.IssuerSigningKey =
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
        option.SaveToken = true; // Overrides Authentication:Jwt:SaveToken.
    })
    .AddValidators();
```

Configure AutoMapper:

```cs
builder.Services.AddAutoMapper(conf => {
    conf.AddProfile<IdentityUserMapper<IdentityUser, IdentityUserDto, string>>();
});
```

Add endpoints (There are more endpoints in samples):

```cs
app.MapGroup("api")
    .WithTags("Authentication APIs")
    .MapLoginApi<IdentityUser, IdentityRole, string>()
    .MapRegisterApi<IdentityUser, IdentityRole, string>();

app.MapGroup("api/account")
    .WithTags("Account APIs")
    .MapAccountApi<IdentityUser, IdentityRole, string>();
```

You can add more services and customize services. Also, there are some [samples](./Samples/) in this repository.

## External Social Logins

### Explicit feature registration and configuration

`AddRuntimeAppsAuthentication<TUser, TRole, TKey>()` registers core Identity managers, the account service, and default user mappers only. Stores and optional features are registered explicitly. The existing `UseJwt`, `AddVerificationServices`, `AddForgotPassword`, `AddRefreshToken`, and provider methods remain available as fluent APIs.

Option sections are `Authentication:Jwt` (the existing `JwtBearerOptions` type), `Authentication:Verification`, `Authentication:ForgotPassword`, `Authentication:RefreshTokens`, and `Authentication:ExternalLogin:Google|Facebook|Microsoft`. Each feature supports configuration binding followed by an action callback. The callback runs after binding, so explicitly assigned values win while untouched values remain from configuration:

```cs
.AddVerificationServices(builder.Configuration)
.AddVerificationServices(options => options.CodeLength = 8)
.AddForgotPassword(builder.Configuration)
.AddRefreshToken(builder.Configuration, options => options.TokenLifetime = TimeSpan.FromDays(14))
.UseJwt(JwtBearerDefaults.AuthenticationScheme, builder.Configuration, options => options.RequireHttpsMetadata = true)
```

The JWT overload binds `Authentication:Jwt` to the selected scheme only. For example, appsettings can hold `SaveToken`, `RefreshInterval`, and `TokenValidationParameters` (such as issuer and audience settings), while the callback can set an unbindable `IssuerSigningKey` from user secrets or an environment variable. Keep the signing key out of committed JSON. The callback overrides only the properties it assigns.

Actions alone remain supported. Defaults are supplied by each options type; configuration binding runs before callbacks; standard Options post-configuration runs afterward; feature validation runs on application startup. External provider options bind JSON values while callbacks can set non-bindable mapper delegates. Keep credentials in user secrets, environment variables, or a secret manager.

Registrations use `TryAdd` to preserve application-provided services. Store interfaces for a single store implementation resolve the same scoped store instance. Use `AddUserMapper` to replace the selected mapper; register custom store interfaces before `AddStores` to retain your implementations. Repeating feature registration appends options configuration in call order and does not duplicate default provider/service registrations.

In many cases you want to add social login to your project, so users can quickly log in and use the application. External login needs to redirect the user to the social login pages which are not useful for API services. This repository provides an easy way to handle external login in ASP.Net core web API. You only should do:

In the frontend part, you could use various libraries based on what framework you are using. For example, you could use [Angular Social Login](https://www.npmjs.com/package/@abacritt/angularx-social-login) in angular and [react-social-login
](https://www.npmjs.com/package/react-social-login) in react. These packages get a token from the client, The only thing that frontend should do is send the token to API and get the application usage token. The implemented API validates and generates needed data.

In the backend, we provide some external login validators. each validator has a configuration that needs to be added to DI.

- **Google Authentication:** For adding google authentication to your API you need to create the Google OAuth 2.0 Client ID and secret [[link](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/google-logins?view=aspnetcore-6.0#create-the-google-oauth-20-client-id-and-secret)] and store them in configuration [[link](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/google-logins?view=aspnetcore-6.0#store-the-google-client-id-and-secret)]. Finally you should add the configuration and service to DI by using these code:

```cs
.AddGoogleExternalLogin(option => {
        option.ClientId = builder.Configuration["Authentication:Google:ClientId"];
        option.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
        option.Mapper = (data)=> GoogleExternalLoginOption<IdentityUser<int>>.UserIdentityMapper<IdentityUser<int>, int>(data);
    })
```

- **Facebook Authentication:** For adding Facebook authentication to your API you need to create the app in Facebook [[link](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/facebook-logins?view=aspnetcore-6.0#create-the-app-in-facebook)] and store them in configuration [[link](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/facebook-logins?view=aspnetcore-6.0#store-the-facebook-app-id-and-secret)]. Finally you should add the configuration and service to DI by using these code:

```cs
.AddFacebookExternalLogin(option => {
        option.ClientId = builder.Configuration["Authentication:Facebook:AppId"];
        option.ClientSecret = builder.Configuration["Authentication:Facebook:AppSecret"];
        option.Mapper = (data) => FacebookExternalLoginOption<IdentityUser<int>>.UserIdentityMapper<IdentityUser<int>, int>(data);
    })
```

- **Microsoft Authentication:** For adding Microsoft authentication to your API you need to create the app in Microsoft developer portal [[link](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/microsoft-logins?view=aspnetcore-6.0#create-the-app-in-microsoft-developer-portal)] and store them in configuration [[link](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/microsoft-logins?view=aspnetcore-6.0#store-the-microsoft-client-id-and-secret)]. Finally you should add the configuration and service to DI by using these code:

```cs
.AddMicrosoftExternalLogin(option => {
        option.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"];
        option.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"];
        option.Mapper = (data) => MicrosoftExternalLoginOption<IdentityUser<int>>.UserIdentityMapper<IdentityUser<int>, int>(data);
    })
```

- **Custome Authentication**: If you want to add other external login to your application you should implement [`IExternalLoginProvider`](RuntimeApps.Authentication/Interface/IExternalLoginProvider.cs) for your external login. Then add it to DI

```cs
builder.Services.AddTransient<IExternalLoginProvider, CustomeExternalLoginProvider>();
```

## License

Distributed under the MIT License. See [LICENSE](./LICENSE) for more information.

## Refresh Token Management

Refresh-token support is optional. Existing applications do not issue or require refresh tokens unless they explicitly call `AddRefreshToken()`.

### Enable refresh tokens with EF Core

Register the EF store after the core refresh-token feature. The application DbContext must include the refresh-token entity in its model:

```cs
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddRuntimeAppsAuthentication<IdentityUser<int>, IdentityRole<int>, int>()
    .AddEfStores<ApplicationDbContext, IdentityUser<int>, IdentityRole<int>, int>()
    .AddEfRefreshTokenStore<ApplicationDbContext, IdentityUser<int>, IdentityRole<int>, int>()
    .AddRefreshToken(options => {
        options.TokenLifetime = TimeSpan.FromDays(30);
        options.RevokeFamilyOnReuse = true;
    })
    .UseJwt(JwtBearerDefaults.AuthenticationScheme, options => {
        // Configure signing key and token validation as usual.
    });
```

In the consumer DbContext, add the entity configuration:

```cs
protected override void OnModelCreating(ModelBuilder modelBuilder) {
    base.OnModelCreating(modelBuilder);
    modelBuilder.AddRefreshTokenEntity<int>();
}
```

Create and apply an EF Core migration after adding the entity. The EF store requires a relational EF Core provider because token rotation is performed transactionally. The raw refresh token is never persisted; only its SHA-256 hash is stored.

### Endpoints

When `AddRefreshToken()` is registered, `MapLoginApi` also maps the following endpoints. The refresh endpoint is automatically rate-limited to 30 requests per minute per remote IP; configure `RefreshRequestsPerMinute` to change the limit. The limiter is in-process; multi-instance deployments should also enforce a shared limit at the gateway or through a distributed rate-limiting layer. When running behind a reverse proxy, configure trusted forwarded headers so the partition key reflects the actual client address. No additional rate-limiting middleware setup is required.

| Endpoint | Behavior |
| --- | --- |
| `POST /refresh` | Rotates the supplied refresh token and issues a new access token |
| `POST /logout` | Revokes the session associated with the supplied refresh token |
| `POST /logout/all` | Revokes all sessions for the authenticated user |

JWT clients send `{ "refreshToken": "..." }` in the request body to `/refresh` and `/logout`. Cookie authentication uses the configured HttpOnly refresh-token cookie. Cookie mode defaults to a Secure, HttpOnly, SameSite=Strict cookie named `__Host-runtimeapps-refresh`; applications may configure its name, path, SameSite mode, and exact cross-origin allowlist through `RefreshTokenOptions.AllowedOrigins`. If SameSite=None is selected, Secure is required. For a cross-origin browser client, configure the expected origin explicitly and review CORS credentials and CSRF requirements before changing cookie defaults.

### Sessions and security behavior

Each successful login creates a separate session (token family). Refresh rotates the token within that family. Reuse of a consumed token revokes only that family, not the user's other sessions. Logout revokes the current family; logout-all revokes all families belonging to the authenticated user. The built-in password-change and add-password endpoints also revoke all refresh-token sessions after a successful password update. Applications implementing password-reset or credential-change flows outside these endpoints should explicitly call `IRefreshTokenService<TKey>.RevokeAllAsync(userId)` after a successful reset.

Refresh tokens are bearer credentials. Clients must store them securely and must not log them. Browser applications should prefer HttpOnly cookies over localStorage. Serialize refresh requests: with strict reuse detection, retrying an old token after a successful rotation (for example, after losing the response) is treated as replay and revokes that session.

Revoking refresh tokens does not immediately invalidate access JWTs already issued. Stateless access tokens remain valid until expiration unless the application adds a separate access-token revocation/session-validation mechanism. Keep access-token lifetimes appropriately short.

### Custom persistence

Applications that do not use the EF integration can implement `IRefreshTokenStore<TKey>` and register it before startup. Store implementations must make `TryRotateAsync` atomic: consuming the old token and persisting its replacement must succeed or fail as one operation. A non-atomic implementation is not safe for production use.


## Registration with email verification

Public registration uses a verification workflow instead of issuing an access token immediately. This is a major-version API change: `IUserAccountService.RegisterAsync` has been replaced by `IRegistrationService<TUser, TKey>`.

### Configure the workflow

Call `AddVerificationServices` when configuring RuntimeApps Authentication. Register a persistent implementation of `IVerificationRequestStore<TKey>` and a delivery implementation of `IVerificationSender<TUser, TKey>`. The EF integration provides a relational store:

```cs
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddRuntimeAppsAuthentication<IdentityUser<int>, IdentityRole<int>, int>()
    .AddVerificationServices(options => {
        options.CodeLength = 6;
        options.CodeLifetime = TimeSpan.FromMinutes(10);
        options.MaximumFailedAttempts = 5;
        options.ResendCooldown = TimeSpan.FromSeconds(60);
        options.MaximumSendsPerHour = 5;
        options.RequireEmailVerificationForExternalLogins = false;
    })
    .AddEfStores<ApplicationDbContext, IdentityUser<int>, IdentityRole<int>, int>();

// In ApplicationDbContext.OnModelCreating:
modelBuilder.AddVerificationRequestEntity<int>();

builder.Services.AddVerificationRequestStore<ApplicationDbContext, int>();
```

The DbContext must use a relational provider. Verification state changes and destination-level rate limits rely on atomic relational operations; EF InMemory is not supported. Add a migration after adding the verification entities. The basic sample uses SQLite because it is relational and supports the required transactions and conditional updates.

The library deliberately does not include an email/SMS delivery implementation. Each application must implement `IVerificationSender<TUser, TKey>` and register it in DI. The basic sample contains a MailKit SMTP implementation that you can use as a starting point:

```cs
builder.Services.Configure<SmtpVerificationOptions>(
    configuration.GetSection(SmtpVerificationOptions.SectionName));
builder.Services.AddScoped<IVerificationSender<IdentityUser<int>, int>,
    MailKitVerificationSender<IdentityUser<int>, int>>();
```

Keep SMTP credentials in user secrets, environment variables, or a secret manager. Persist and share the ASP.NET Core Data Protection key ring across application instances. The sample uses `EnsureCreated` only to create its local development database without checked-in migration files; `EnsureCreated` does not apply or update migrations. Production applications should create and apply EF Core migrations as part of deployment.

### Registration endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/register` | Create or recover a pending account and send a verification code |
| POST | `/register/verify` | Verify the code and receive an authentication token |
| POST | `/register/resend` | Send a replacement code; the previous code becomes invalid |

The API returns an opaque, cryptographically random verification handle. Only its SHA-256 lookup hash is stored; the database request ID is never exposed. The code is protected using ASP.NET Core Data Protection and bound to the user, request, purpose, channel, and destination.

Default limits are six numeric digits, ten-minute lifetime, five failed attempts, a 60-second resend cooldown, and five sends per destination/purpose/channel per hour. A successful verification is single-use. A resend rotates the code. The EF store uses relational transactions and conditional updates for concurrent operations.

Repeating registration recovers an existing pending account if the client lost its handle. The existing account is reused unchanged: registration does not update its username, phone number, email, password, or any custom properties. If the user needs to change account information, provide a separate authenticated account-management flow or a dedicated recovery process.

Confirmed accounts are never modified or registered again; the API returns the same generic response to prevent account enumeration.

### Administrator provisioning

Map `MapAdminUserApi<TUser, TUserDto, TKey>()` separately from public registration. By default, the endpoint requires the `Administrator` role. Alternatively, pass a named authorization policy. It creates an already-confirmed user, returns the user DTO, and does not issue an authentication token.

### External login policy

External provider login does not require a second email challenge by default. Set `RequireEmailVerificationForExternalLogins = true` to require email verification before issuing an application token when the provider email is not trusted.

External authentication and email confirmation remain separate. The default trust policy accepts verified Google Gmail/Googlemail addresses and verified Google Workspace addresses when the signed hosted-domain claim matches the email domain. Facebook and Microsoft email claims are not trusted by default. Developers can replace `IExternalLoginEmailTrustPolicy<TUser>`.

External identities are not automatically linked to an existing local account based on a matching email address. Linking must be initiated from an authenticated account-management flow.

### Migration note

This is a breaking major-version change. Remove calls to the old immediate-token registration API and use the verification endpoints. Applications must add the verification entities to their relational DbContext and create a migration, configure a persistent request store and sender, and review administrator authorization policy. No production in-memory verification store is provided.


## Optional forgot-password API

Password recovery is an optional feature. It reuses the verification-request store, protected verifier, sender, expiration, send limits, and one-time request consumption. It is not mapped by \`MapLoginApi\`, \`MapRegisterApi\`, or \`MapAccountApi\`; explicitly call \`MapForgotPasswordApi<TUser, TKey>()\` only when you want to expose it.

Register the feature after \`AddVerificationServices()\`:

\`\`\`cs
.AddVerificationServices()
.AddForgotPassword(options => {
    options.Method = ForgotPasswordMethod.VerificationCode;
    // For link mode instead:
    // options.Method = ForgotPasswordMethod.Link;
    // options.FrontendResetUrl = "https://frontend.example.com/reset-password";
})
\`\`\`

Register a persistent \`IVerificationRequestStore<TKey>\` and an \`IVerificationSender<TUser, TKey>\` as described in the email-verification section. Then map the endpoints independently:

\`\`\`cs
app.MapGroup("api")
    .MapForgotPasswordApi<IdentityUser<int>, int>();
\`\`\`

The mapped endpoints are:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | \`/forgot-password\` | Accepts \`{ "email": "person@example.com" }\` and sends recovery instructions |
| POST | \`/reset-password\` | Accepts \`{ "verificationHandle": "...", "credential": "...", "newPassword": "..." }\` and resets the password |

The request endpoint always returns the same generic response, including for unknown, unconfirmed, or rate-limited accounts. Recovery is sent only to an existing account with a confirmed email address. In code mode, the response includes an opaque verification handle. For unknown, unconfirmed, or rate-limited accounts, it returns a random handle that does not correspond to a stored request. In link mode, the handle is omitted from the API response and is embedded in the emailed frontend link.

In \`VerificationCode\` mode, the sender receives the numeric code generated by the configured \`IVerificationCodeGenerator\`. In \`Link\` mode, the library generates an ASP.NET Core Identity password-reset token using the configured Identity token provider; the default Data Protection provider also binds the token to the user's security stamp. The sender can create a frontend URL with `context.CreateVerificationUrl(token)`, which combines the request handle and token into a URL fragment of the form \`https://frontend.example.com/reset-password#handle=...&token=...\`. The browser opens the frontend page; the frontend extracts the fragment and submits the handle, token, and new password to the backend reset endpoint. The URL fragment is not sent in the initial HTTP request. The frontend should immediately remove the fragment from browser history and avoid exposing it to analytics or third-party scripts. Do not consume the credential on page load: email security scanners may open links automatically. The configured Identity password-reset token provider's lifetime should be at least as long as the verification lifetime; the verification request still enforces the shorter effective expiry.

The configured sender controls the actual email template and delivery. The sample MailKit sender demonstrates both modes. Link mode requires an absolute HTTPS \`FrontendResetUrl\`.

Before consuming the recovery request, the service runs the configured Identity password validators. After successful credential verification, it uses Identity's password-reset token and \`ResetPasswordAsync\` to perform the update. If refresh-token support is registered, all refresh-token sessions for that user are revoked after a successful reset. Already-issued stateless access JWTs remain valid until expiry unless the application has a separate access-token revocation mechanism.

Use an external rate limiter at the API gateway or application edge as well as the verification store's per-destination send and failed-attempt limits. Persist and share the ASP.NET Core Data Protection key ring across instances.
