using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.Extensions;
using RuntimeApps.Authentication.EF.Extensions;
using RuntimeApps.Authentication.Sample.CookieAuthentication;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using RuntimeApps.Authentication.Model;
using System.Text.Json.Serialization;
using RuntimeApps.Authentication.Controller;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddCookie(JwtBearerDefaults.AuthenticationScheme)
    .AddRuntimeAppsAuthentication<IdentityUser<int>, IdentityRole<int>, int>()
    .AddEfStores<ApplicationDbContext, IdentityUser<int>, IdentityRole<int>, int>()
    .AddValidators();

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

app.MapGroup("api")
    .WithTags("Authentication APIs")
    .MapLoginApi<IdentityUser<int>, IdentityUserDto<int>, int>()
    .MapRegisterApi<IdentityUser<int>, IdentityUserDto<int>, int>();

app.MapGroup("api/user")
    .WithTags("Account APIs")
    .MapAccountApi<IdentityUser<int>, IdentityUserDto<int>, int>();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action=Index}/{id?}");

app.Run();
