# Basic user manager sample
The basic user manager implementation of RuntimeApps.Authentication. This sample Uses `int` as key of user models.

In this sample, the usage of exterrnal login is provided. So you can configure your own external login and use it.

## File descriptions

File | Usage 
--- | ---
[ApplicationDbContext](./ApplicationDbContext.cs) | The Entity Framework core Db Context in the application. It inharients `IdentityDbContext` which is default implemetation of ASP.net core identity in Entity framework core. You could costomize the tables and add your tables in this file.
[Program](./Program.cs) | The main configuration of asp.net core application. You should add commented codes to your project.


## User mapping

The API endpoints convert between your identity user (`TUser`) and the DTO returned to clients (`TUserDto`)
through one small interface, so the library has no dependency on a mapping library:

```cs
public interface IUserMapper<TUser, TUserDto> {
    TUserDto ToDto(TUser user);   // login, register, account and user-get endpoints
    TUser ToUser(TUserDto dto);   // register endpoint only
}
```

### Out of the box

`IdentityUserDto<TKey>` (and `IdentityUserDto` for string keys) work with no mapper setup. The built-in
`DefaultIdentityUserMapper` copies `Id`, `UserName`, `Email`, `PhoneNumber` and `TwoFactorEnabled` to the DTO.
When registering, it only reads `UserName`, `Email` and `PhoneNumber` from the DTO.

### Your own DTO or mapper

Register a mapper after `AddRuntimeAppsAuthentication`. Registering a mapper for a DTO replaces any earlier one
for that DTO, so the last call wins.

```cs
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddRuntimeAppsAuthentication<AppUser, IdentityRole, string>()
    .AddEfStores<ApplicationDbContext, AppUser, IdentityRole, string>()
    .AddUserMapper<AppUserDto, AppUserMapper>()   // or one of the options below
    ...
```

**Inline delegates**

```cs
.AddUserMapper<AppUserDto>(
    toDto: u => new AppUserDto { Id = u.Id, UserName = u.UserName, Email = u.Email, DisplayName = u.DisplayName },
    toUser: d => new AppUser { UserName = d.UserName, Email = d.Email, DisplayName = d.DisplayName })
```

**Hand-written class**

```cs
public class AppUserMapper : IUserMapper<AppUser, AppUserDto> {
    public AppUserDto ToDto(AppUser u) => new() { Id = u.Id, UserName = u.UserName, Email = u.Email };
    public AppUser ToUser(AppUserDto d) => new() { UserName = d.UserName, Email = d.Email };
}
```

**Mapperly** (source generated, MIT)

```cs
[Mapper]
public partial class AppUserMapper : IUserMapper<AppUser, AppUserDto> {
    public partial AppUserDto ToDto(AppUser user);
    public partial AppUser ToUser(AppUserDto dto);
}
```

**Mapster**

```cs
public class AppUserMapper : IUserMapper<AppUser, AppUserDto> {
    public AppUserDto ToDto(AppUser user) => user.Adapt<AppUserDto>();
    public AppUser ToUser(AppUserDto dto) => dto.Adapt<AppUser>();
}
```

**AutoMapper** (keep using it if you want)

```cs
public class AppUserMapper(IMapper mapper) : IUserMapper<AppUser, AppUserDto> {
    public AppUserDto ToDto(AppUser user) => mapper.Map<AppUserDto>(user);
    public AppUser ToUser(AppUserDto dto) => mapper.Map<AppUser>(dto);
}
```

By default a mapper registered with `AddUserMapper<TUserDto, TMapper>()` is scoped. Pass
`ServiceLifetime.Singleton` for stateless mappers such as Mapperly's.

### Endpoints

Endpoint registration is unchanged apart from the DTO type argument, for example:

```cs
app.MapGroup("api").MapAuthenticationApi<IdentityUser, IdentityUserDto, string>()
                   .MapRegistrationApi<IdentityUser, IdentityUserDto, string>();
app.MapGroup("api").MapVerificationApi<IdentityUser, IdentityUserDto, string>();
app.MapGroup("api/account").MapAccountManagementApi<IdentityUser, IdentityUserDto, string>();
```


## Email verification

The basic sample uses SQLite (a relational provider is required by the atomic verification store) and demonstrates an SMTP sender implemented with MailKit. MailKit is referenced only by this sample; the authentication library itself does not provide or require an email-delivery implementation. The sample defaults to a local SMTP development server at `localhost:1025` without TLS. Run Mailpit or configure SMTP through environment variables/user secrets before testing registration.

The sample's DbContext includes the verification entities:

```cs
protected override void OnModelCreating(ModelBuilder modelBuilder) {
    base.OnModelCreating(modelBuilder);
    modelBuilder.AddVerificationRequestEntity<int>();
}
```

The service setup calls `AddVerificationServices()`, registers `AddVerificationRequestStore<ApplicationDbContext, int>()`, and registers the sample's `IVerificationSender<IdentityUser<int>, int>` implementation. In your own application, implement `IVerificationSender<TUser, TKey>` for your delivery provider (SMTP, email API, SMS, etc.) and register it in dependency injection. The MailKit implementation in this sample is an example, not a library integration.

The registration flow is:

1. `POST /api/register` creates a pending account and sends a code.
2. `POST /api/register/verify` accepts the opaque verification handle and code, confirms the email, and issues the application token.
3. `POST /api/register/resend` rotates the code while keeping the same handle.

The sample uses SQLite because the verification store requires a relational provider; EF Core's InMemory provider does not support the transactional/atomic operations used by the verification store. In Development, `EnsureCreated` initializes the sample database directly from the model because this sample does not include migration files. `EnsureCreated` does not apply later schema changes; production applications should use EF Core migrations.

The sample also maps `POST /api/admin/users` under the named `Admin` policy. The policy requires the `Administrator` role. The endpoint creates an already-confirmed account and returns the user DTO without issuing a token.

Do not use the sample SMTP defaults in production. Configure TLS, secrets, persistent Data Protection keys, database migrations, and operational cleanup for expired verification records and send-history rows.


## Forgot password

The basic sample explicitly enables and maps the optional forgot-password API. It defaults to numeric verification codes:

\`\`\`cs
.AddVerificationServices()
.AddForgotPassword(options => {
    options.Method = ForgotPasswordMethod.VerificationCode;
})
\`\`\`

To use frontend-hosted reset links instead, configure an HTTPS frontend page:

\`\`\`cs
.AddForgotPassword(options => {
    options.Method = ForgotPasswordMethod.Link;
    options.FrontendResetUrl = "https://frontend.example.com/reset-password";
})
\`\`\`

The endpoint is mapped separately from the other authentication endpoints:

\`\`\`cs
app.MapGroup("api")
    .MapPasswordRecoveryApi<IdentityUser<int>, int>();
\`\`\`

The frontend receives the reset handle and token in the URL fragment, removes them from the address bar immediately, and submits them with the new password to \`POST /api/reset-password\`. Loading the frontend link does not consume the credential. In code mode, the API response supplies the handle and the email supplies the code. In link mode, the sender uses `context.CreateVerificationUrl(token)` to create the frontend reset link; no handle is returned in the API response.
