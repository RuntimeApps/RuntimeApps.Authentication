using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.Sample.Services;
using RuntimeApps.Authentication.Sample.Model;
using Microsoft.IdentityModel.Tokens;
using RuntimeApps.Authentication.Endpoints.Account;
using RuntimeApps.Authentication.Endpoints.PasswordRecovery;
using RuntimeApps.Authentication.Endpoints.RefreshTokens;
using RuntimeApps.Authentication.Endpoints.Roles;
using RuntimeApps.Authentication.Endpoints.Users;
using RuntimeApps.Authentication.EF.Features.RefreshTokens.Configurations;
using RuntimeApps.Authentication.EF.Features.Verification.Configurations;
using RuntimeApps.Authentication.EF.DependencyInjection;
using RuntimeApps.Authentication.DependencyInjection;
using RuntimeApps.Authentication.Shared.Extensions;
using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
using RuntimeApps.Authentication.Features.PasswordRecovery.Models;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
using RuntimeApps.Authentication.Features.Registration.Models;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Identity.Models;
using RuntimeApps.Authentication.Shared.Models;
using RuntimeApps.Authentication.Sample;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.PasswordRecovery.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.Registration.Contracts;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Authentication") ?? "Data Source=authentication.db"));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    //Add default services of RuntimeApps application
    .AddRuntimeAppsAuthentication<IdentityUser<int>, IdentityRole<int>, int>()
    .AddVerificationServices(builder.Configuration)
    .AddVerificationServices(options => {
        // This code override takes precedence over Authentication:Verification:CodeLength.
        options.CodeLength = 6;
    })
    .AddForgotPassword(builder.Configuration, options => {
        // Choose Link and configure FrontendResetUrl to enable frontend-hosted reset links.
        options.Method = ForgotPasswordMethod.VerificationCode;
    })
    //Add implemetation of entity framework core user stores.
    .AddEfStores<ApplicationDbContext, IdentityUser<int>, IdentityRole<int>, int>()
    // Add default mapper between IdentityUser and IdentityUserDto
    .AddDefaultUserMapper<IdentityUserDto<int>>()
    //Add Jwt authentication serices to application
    .UseJwt(JwtBearerDefaults.AuthenticationScheme, option => {
        SymmetricSecurityKey signingKey = new(Encoding.ASCII.GetBytes(builder.Configuration["Jwt:Key"]));
        option.RequireHttpsMetadata = false;
        option.SaveToken = true;
        option.RefreshOnIssuerKeyNotFound = false;
        option.RefreshInterval = TimeSpan.FromMinutes(int.Parse(builder.Configuration["Jwt:ExpireInMinute"]));
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
    //Add basic validations which is implemeted by ASP.Net core identity
    .AddValidators()
    //Add validator services of google authentication
    .AddGoogleExternalLogin(builder.Configuration, option => {
        // Mapper of google model to user model
        option.Mapper = (data) => GoogleExternalLoginOption<IdentityUser<int>>.UserIdentityMapper<IdentityUser<int>, int>(data);
    })
    //Add validator services of facebook authentication
    .AddFacebookExternalLogin(builder.Configuration, option => {
        // Mapper of facebook model to user model
        option.Mapper = (data) => FacebookExternalLoginOption<IdentityUser<int>>.UserIdentityMapper<IdentityUser<int>, int>(data);
    })
    //Add validator services of microsoft authentication
    .AddMicrosoftExternalLogin(builder.Configuration, option => {
        // Mapper of microsot model to user model
        option.Mapper = (data) => MicrosoftExternalLoginOption<IdentityUser<int>>.UserIdentityMapper<IdentityUser<int>, int>(data);
    });

builder.Services.AddVerificationRequestStore<ApplicationDbContext, int>();
builder.Services.AddOptions<SmtpVerificationOptions>()
    .BindConfiguration(SmtpVerificationOptions.SectionName)
    .Validate(options => options.IsValid(), "SMTP verification options are invalid.")
    .ValidateOnStart();
builder.Services.AddScoped<IVerificationSender<IdentityUser<int>, int>,
    MailKitVerificationSender<IdentityUser<int>, int>>();

builder.Services.AddAuthorization(options => options.AddPolicy("Admin", policy => policy.RequireRole("Administrator")));

builder.Services.AddControllers()
    .AddJsonOptions(option => {
        option.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        option.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
    });

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if(app.Environment.IsDevelopment()) {
    using(var scope = app.Services.CreateScope()) {
        var services = scope.ServiceProvider;
        try {
            var context = services.GetRequiredService<ApplicationDbContext>();
            // The sample has no checked-in migrations. EnsureCreated creates its demo schema
            // directly from the EF model; real applications should use EF Core migrations.
            context.Database.EnsureCreated();
        } catch(Exception ex) {
            var logger = services.GetRequiredService<ILogger<Program>>();
            logger.LogError(ex, "An error occurred while initializing the sample database.");
        }
    }

    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapGroup("api")
    .WithTags("Authentication APIs")
    .MapLoginApi<IdentityUser<int>, IdentityUserDto<int>, int>()
    .MapRegisterApi<IdentityUser<int>, IdentityUserDto<int>, int>()
    .MapForgotPasswordApi<IdentityUser<int>, int>();

app.MapGroup("api")
    .WithTags("Administrator APIs")
    .MapAdminUserApi<IdentityUser<int>, IdentityUserDto<int>, int>("Admin");

app.MapGroup("api/account")
    .WithTags("Account APIs")
    .MapAccountApi<IdentityUser<int>, IdentityUserDto<int>, int>();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action=Index}/{id?}");

app.Run();
