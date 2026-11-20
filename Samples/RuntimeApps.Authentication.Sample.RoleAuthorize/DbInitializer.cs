using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.PasswordRecovery.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.Registration.Contracts;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;
namespace RuntimeApps.Authentication.Sample.RoleAuthorize {
    public static class DbInitializer {
        public static void Initialize(ApplicationDbContext context, IUserManager<IdentityUser<int>> userManager, IRoleManager<IdentityRole<int>> roleManager) {
            context.Database.Migrate();

            if(context.Users.Any()) {
                return;
            }

            foreach(var roleName in RoleConsts.AllRoles()) {
                var addRoleResult = roleManager.CreateAsync(new IdentityRole<int>(roleName)).Result;
                if(!addRoleResult.Succeeded)
                    Console.WriteLine($"Cannot add role {roleName}: {string.Join(',', addRoleResult.Errors.Select(e => e.Description))}");
            }

            var user = new IdentityUser<int>("Admin");
            var password = "P@ssw0rd";
            var userAddResult = userManager.CreateAsync(user, password).Result;

            var userRoleAddResult = userManager.AddToRolesAsync(user, RoleConsts.AllRoles()).Result;

            Console.WriteLine($"Admin user information:");
            Console.WriteLine($"UserName: {user.UserName}");
            Console.WriteLine($"Password: {password}");
        }
    }
}
