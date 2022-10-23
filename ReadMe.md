# RuntimeApps.Authentication

The UserManager of ASP.Net core is good for most of porposes and it implements in various type of [Databases](https://github.com/dotnet/aspnetcore/tree/main/src/Identity#community-maintained-store-providers).

But there is some problems in this implementation. I list some of them that I have tried to improve it:

- The Identity server of ASP.Net core has used [Identity Server 4](https://github.com/IdentityServer/IdentityServer4) however it has been archived and moved to [Duende Software](https://github.com/duendesoftware) which is not free. But I beleive in most cases softwares doesn't need Identity Server and They want to have simple user managment. So this repository only sopport simple usage of user managers based on  that might be useful for your project.
- The default implementation of ASP.Net core user manager has been depended to MVC (implements razor pages). This repository focuses on Web API applications that has seprate frontend and backend code. So you can esaly use APIs on user managers and external logins.
- Some implemetations of ASP.Net core user management should be improvied. For example, `UserManager<TUser>` doesn't inharent any interfaces which makes very hard to write tests. In this repository I have tried to solve some of these problems.
- Asp.Net core external social logins works based on redirect to social login page which is not useful in ASP.Net core Web APIs. ASP.Net core implements this by using MVC and managing the request responses, But this repository has implementes social login token validation which is useful for APIs that doesn't access user pages (Mobile apps and frontend teches).

## Getting Started

For using this library do the steps:

### Install packages:

Install `RuntimeApps.Authentication` package which implements base services.

```Install-Package RuntimeApps.Authentication```

If you want to use EntityFrameworkCore implemetation of Authentication install the pcakge

```Install-Package RuntimeApps.Authentication.EF```

Or you can install other implementation of store [link](https://github.com/dotnet/aspnetcore/tree/main/src/Identity#community-maintained-store-providers)

### Create needed classes

1. Create `AccountController` class which inharient `BaseAccountController` and define route and other implemetation if you need.

2. Create your own `ApplicationDbContext` and inharient `IdentityDbContext`

### Configure Services

Add required services to DI:

```cs
builder.Services.AddAuthentication()
    .AddRuntimeAppsAuthentication<IdentityUser<int>, IdentityRole<int>, int>()
    .AddStores<ApplicationDbContext, IdentityUser<int>, IdentityRole<int>, int>()
    .UseJwt(option => {
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
    });
```

You can add more services and customise service. Also there is some [samples](./Samples/) in this repository.

## External Social Logins

In many cases you want to add social login to your project, so users can easily login and use the application. External login needs to redirect user to the social login pages which is not useful for API services. This repository provides easy way to handling external login in ASP.Net core web API. You only shoud do:

In frontend part you could use various library based on what framework you are using. For example you could use [Angular Social Login](https://www.npmjs.com/package/@abacritt/angularx-social-login) in angular and [react-social-login
](https://www.npmjs.com/package/react-social-login) in react. These packages get a token to client, The only thing that frontend should do is that send the token to API and get application usage token. The implemeted API validate and generate needed data.

In backend we provide some external login validator. each validator has a configuration that needs to be added to DI.

- **Google Authentication:** For adding google authentication to your api you need to create the Google OAuth 2.0 Client ID and secret [[link](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/google-logins?view=aspnetcore-6.0#create-the-google-oauth-20-client-id-and-secret)] and store them in configuration [[link](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/google-logins?view=aspnetcore-6.0#store-the-google-client-id-and-secret)]. Finaly you should add the configuration and service to DI by using these code:

```cs
.AddGoogleExternalLogin(option => {
        option.ClientId = builder.Configuration["Authentication:Google:ClientId"];
        option.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
        option.Mapper = (data)=> GoogleExternalLoginOption<IdentityUser<int>>.UserIdentityMapper<IdentityUser<int>, int>(data);
    })
```

- **Facebook Authentication:** For adding facebook authentication to your api you need to create the app in facebook [[link](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/facebook-logins?view=aspnetcore-6.0#create-the-app-in-facebook)] and store them in configuration [[link](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/facebook-logins?view=aspnetcore-6.0#store-the-facebook-app-id-and-secret)]. Finaly you should add the configuration and service to DI by using these code:

```cs
.AddFacebookExternalLogin(option => {
        option.ClientId = builder.Configuration["Authentication:Facebook:AppId"];
        option.ClientSecret = builder.Configuration["Authentication:Facebook:AppSecret"];
        option.Mapper = (data) => FacebookExternalLoginOption<IdentityUser<int>>.UserIdentityMapper<IdentityUser<int>, int>(data);
    })
```

- **Microsoft Authentication:** For adding microsoft authentication to your api you need to create the app in microsoft developer portal [[link](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/microsoft-logins?view=aspnetcore-6.0#create-the-app-in-microsoft-developer-portal)] and store them in configuration [[link](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/microsoft-logins?view=aspnetcore-6.0#store-the-microsoft-client-id-and-secret)]. Finaly you should add the configuration and service to DI by using these code:

```cs
.AddMicrosoftExternalLogin(option => {
        option.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"];
        option.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"];
        option.Mapper = (data) => MicrosoftExternalLoginOption<IdentityUser<int>>.UserIdentityMapper<IdentityUser<int>, int>(data);
    })
```

- **Custome Othentication**: If you want to add other external login to your application you should implement [`IExternalLoginProvider`](RuntimeApps.Authentication/Interface/IExternalLoginProvider.cs) for your external login. Then add it to DI

```cs
builder.Services.AddTransient<IExternalLoginProvider, CustomeExternalLoginProvider>();
```

## License

Distributed under the MIT License. See [LICENSE](./LICENSE) for more information.
