using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RuntimeApps.Authentication.EF.Extensions;
using RuntimeApps.Authentication.Extensions;
using RuntimeApps.Authentication.Model;
using RuntimeApps.Authentication.Sample;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    //Add default services of RuntimeApps application
    .AddRuntimeAppsAuthentication<IdentityUser<int>, IdentityRole<int>, int>()
    //Add implemetation of entity framework core user stores.
    .AddEfStores<ApplicationDbContext, IdentityUser<int>, IdentityRole<int>, int>()
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
    .AddGoogleExternalLogin(option => {
        option.ClientId = builder.Configuration["Authentication:Google:ClientId"];
        option.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
        // Mapper of google model to user model
        option.Mapper = (data) => GoogleExternalLoginOption<IdentityUser<int>>.UserIdentityMapper<IdentityUser<int>, int>(data);
    })
    //Add validator services of facebook authentication
    .AddFacebookExternalLogin(option => {
        option.ClientId = builder.Configuration["Authentication:Facebook:AppId"];
        option.ClientSecret = builder.Configuration["Authentication:Facebook:AppSecret"];
        // Mapper of facebook model to user model
        option.Mapper = (data) => FacebookExternalLoginOption<IdentityUser<int>>.UserIdentityMapper<IdentityUser<int>, int>(data);
    })
    //Add validator services of microsoft authentication
    .AddMicrosoftExternalLogin(option => {
        option.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"];
        option.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"];
        // Mapper of microsot model to user model
        option.Mapper = (data) => MicrosoftExternalLoginOption<IdentityUser<int>>.UserIdentityMapper<IdentityUser<int>, int>(data);
    });

// Add Automapper with IdentityUserMapper. If you want to have your output model, you can override this class.
builder.Services.AddAutoMapper(conf => {
    conf.AddProfile<IdentityUserMapper<IdentityUser<int>, IdentityUserDto<int>, int>>();
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

app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action=Index}/{id?}");

app.Run();
