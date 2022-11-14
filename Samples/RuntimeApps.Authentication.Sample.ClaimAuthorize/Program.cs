using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.Extensions;
using RuntimeApps.Authentication.Model;
using RuntimeApps.Authentication.Sample.ClaimAuthorize;
using RuntimeApps.Authentication.EF.Extensions;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;
using RuntimeApps.Authentication.Interface;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddRuntimeAppsAuthentication<IdentityUser<int>, IdentityRole<int>, int>()
    .AddEfStores<ApplicationDbContext, IdentityUser<int>, IdentityRole<int>, int>()
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

builder.Services.AddAutoMapper(conf => {
    conf.AddProfile<IdentityUserMapper<IdentityUser<int>, IdentityUserDto<int>, int>>();
});

builder.Services.AddAuthorization(option => {
    foreach(var item in PolicyConsts.GetAllPolicies()) {
        if(item.ClaimValues?.Any() == true)
            option.AddPolicy(item.PolicyName, policy => policy.RequireClaim(item.ClaimType, item.ClaimValues));
        else
            option.AddPolicy(item.PolicyName, policy => policy.RequireClaim(item.ClaimType));
    }
});

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
            var dbContext = services.GetRequiredService<ApplicationDbContext>();
            var userManager = services.GetRequiredService<IUserManager<IdentityUser<int>>>();
            var roleManager = services.GetRequiredService<IRoleManager<IdentityRole<int>>>();
            DbInitializer.Initialize(dbContext, userManager, roleManager);
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

app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action=Index}/{id?}");

app.Run();
