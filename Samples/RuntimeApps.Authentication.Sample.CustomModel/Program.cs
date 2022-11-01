using System.Text;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using RuntimeApps.Authentication.EF.Extensions;
using RuntimeApps.Authentication.Extensions;
using RuntimeApps.Authentication.Model;
using RuntimeApps.Authentication.Sample.CustomModel;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString));

builder.Services.AddAuthentication()
    .AddRuntimeAppsAuthentication<User, Role, int>()
    .AddEfStores<ApplicationDbContext, User, Role, int>()
    .UseJwt(option => {
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
    .AddValidators(identityOption => {
        identityOption.Password.RequiredLength = 8;
        identityOption.Password.RequiredUniqueChars = 2;
        identityOption.Password.RequireDigit = true;
        identityOption.Password.RequireUppercase = true;
        identityOption.Password.RequireLowercase = true;

        identityOption.User.RequireUniqueEmail = true;
    })
    .AddGoogleExternalLogin(option => {
        option.ClientId = builder.Configuration["Authentication:Google:ClientId"];
        option.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
        option.Mapper = (data) => {
            var user = GoogleExternalLoginOption<User>.UserIdentityMapper<User, int>(data);
            user.Name = data.Name;
            user.ProfilePicture = data.Picture;
            return user;
        };
    })
    .AddFacebookExternalLogin(option => {
        option.ClientId = builder.Configuration["Authentication:Facebook:AppId"];
        option.ClientSecret = builder.Configuration["Authentication:Facebook:AppSecret"];
        option.Mapper = (data) => {
            var user = FacebookExternalLoginOption<User>.UserIdentityMapper<User, int>(data);
            user.Name = data.Name;
            user.ProfilePicture = data.Picture?.Data?.Url;
            return user;
        };
    })
    .AddMicrosoftExternalLogin(option => {
        option.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"];
        option.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"];
        option.Mapper = (data) => {
            var user = MicrosoftExternalLoginOption<User>.UserIdentityMapper<User, int>(data);
            user.Name = data.Claims.FirstOrDefault(c => c.Type == "name")?.Value;
            return user;
        };
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
            context.Database.EnsureCreated();
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
