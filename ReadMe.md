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

1. Create `AccountController` class which inherit `BaseAccountController` and define the route and other implementation if you need them.

2. Create your own `ApplicationDbContext` and inherent `IdentityDbContext`

### Configure Services

Add required services to DI:

```cs
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
    .AddEfStores<ApplicationDbContext, IdentityUser, IdentityRole, string>()
    .UseJwt(JwtBearerDefaults.AuthenticationScheme, option => {
        SymmetricSecurityKey signingKey = new(Encoding.ASCII.GetBytes(builder.Configuration["Jwt:Key"]));
        option.RequireHttpsMetadata = false;
        option.SaveToken = true;
        option.RefreshOnIssuerKeyNotFound = false;
        option.TokenValidationParameters = new TokenValidationParameters {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ValidateIssuer = false,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidateAudience = true,
            ValidAudience = builder.Configuration["Jwt:Audience"],
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            RequireExpirationTime = true,
        };
    })
    .AddValidators();
```

Configure AutoMapper:

```cs
builder.Services.AddAutoMapper(conf => {
    conf.AddProfile<IdentityUserMapper<IdentityUser, IdentityUserDto, string>>();
});
```

You can add more services and customize services. Also, there are some [samples](./Samples/) in this repository.

## External Social Logins

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
