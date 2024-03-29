using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RuntimeApps.Authentication.Controller;
using RuntimeApps.Authentication.EF.Extensions;
using RuntimeApps.Authentication.Extensions;
using RuntimeApps.Authentication.Model;
using RuntimeApps.Authentication.Sample.CustomValidation;
using RuntimeApps.Authentication.Sample.CustomValidation.PasswordValidators;
using RuntimeApps.Authentication.Sample.CustomValidation.UserValidators;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString));

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
    .AddValidators(identityOption => {
        identityOption.Password.RequiredLength = 8;
        identityOption.Password.RequiredUniqueChars = 2;
        identityOption.Password.RequireDigit = true;
        identityOption.Password.RequireUppercase = true;
        identityOption.Password.RequireLowercase = true;

        identityOption.User.RequireUniqueEmail = true;
    });

builder.Services.AddScoped<IPasswordValidator<IdentityUser>, PasswordDoesNotContainUsername>()
                .AddScoped<IUserValidator<IdentityUser>, UserNameMustBeEmailValidator>();

builder.Services.AddAutoMapper(conf => {
    conf.AddProfile<IdentityUserMapper<IdentityUser, IdentityUserDto, string>>();
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
    .MapLoginApi<IdentityUser, IdentityRole, string>()
    .MapRegisterApi<IdentityUser, IdentityRole, string>();

app.MapGroup("api/account")
    .WithTags("Account APIs")
    .MapAccountApi<IdentityUser, IdentityRole, string>();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action=Index}/{id?}");

app.Run();
