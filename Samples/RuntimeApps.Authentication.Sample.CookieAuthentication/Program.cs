using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
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
using RuntimeApps.Authentication.Sample.CookieAuthentication;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString));

builder.Services.AddAuthentication(Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie()
    .AddRuntimeAppsAuthentication<IdentityUser<int>, IdentityRole<int>, int>()
    .AddEfStores<ApplicationDbContext, IdentityUser<int>, IdentityRole<int>, int>()
    .AddEfRefreshTokenStore<ApplicationDbContext, IdentityUser<int>, IdentityRole<int>, int>()
    .AddRefreshToken(options => {
        options.TokenLifetime = TimeSpan.FromDays(30);
        options.RevokeFamilyOnReuse = true;
    })
    .AddCookieAuthenticationSessionIssuer()
    .AddDefaultUserMapper<IdentityUserDto<int>>()
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
    using(var scope = app.Services.CreateScope()) {
        var services = scope.ServiceProvider;
        try {
            var context = services.GetRequiredService<ApplicationDbContext>();
            context.Database.Migrate();
        } catch(Exception ex) {
            var logger = services.GetRequiredService<ILogger<Program>>();
            logger.LogError(ex, "An error occurred while seeding the database.");
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
    .MapAuthenticationApi<IdentityUser<int>, IdentityUserDto<int>, int>();

app.MapGroup("api/user")
    .WithTags("Account APIs")
    .MapAccountManagementApi<IdentityUser<int>, IdentityUserDto<int>, int>();

app.MapGroup("api/session").MapSessionApi<IdentityUser<int>, int>();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action=Index}/{id?}");

app.Run();
