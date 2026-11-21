using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using RuntimeApps.Authentication.Endpoints.Account;
using RuntimeApps.Authentication.Endpoints.PasswordRecovery;
using RuntimeApps.Authentication.Endpoints.RefreshTokens;
using RuntimeApps.Authentication.Endpoints.Roles;
using RuntimeApps.Authentication.Endpoints.Users;
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
using RuntimeApps.Authentication.Sample.CustomStore.Store;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<IStoreUnitOfWork, StoreUnitOfWork>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddRuntimeAppsAuthentication<IdentityUser, IdentityRole, string>()
    .AddStores<CustomUserStore, CustomRoleStore>()
    .AddDefaultUserMapper<IdentityUserDto>()
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
    .AddValidators();

builder.Services.AddControllers()
    .AddJsonOptions(option => {
        option.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        option.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
    });

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if(app.Environment.IsDevelopment()) {
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapGroup("api")
    .WithTags("Authentication APIs")
    .MapAuthenticationApi<IdentityUser, IdentityUserDto, string>();

app.MapGroup("api/account")
    .WithTags("Account APIs")
    .MapAccountManagementApi<IdentityUser, IdentityUserDto, string>();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action=Index}/{id?}");

app.Run();
