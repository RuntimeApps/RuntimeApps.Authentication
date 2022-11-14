using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Sample.ClaimAuthorize {
    public class DbInitializer {
        public static void Initialize(ApplicationDbContext context, IUserManager<IdentityUser<int>> userManager, IRoleManager<IdentityRole<int>> roleManager) {
            context.Database.Migrate();

            if(context.Users.Any()) {
                return;
            }

            var role = new IdentityRole<int>("Admin");
            var addRoleResult = roleManager.CreateAsync(role).Result;
            if(!addRoleResult.Succeeded)
                    Console.WriteLine($"Cannot add role {role.Name}: {string.Join(',', addRoleResult.Errors.Select(e => e.Description))}");

            var addRoleClaim = roleManager.AddClaimAsync(role, new Claim(ClaimConsts.UserManagerClaim.ClaimType, ClaimConsts.UserManagerClaim.ClaimValueDescription.Keys.Order().Last()));

            var user = new IdentityUser<int>("Admin");
            var password = "P@ssw0rd";
            var userAddResult = userManager.CreateAsync(user, password).Result;

            var userRoleAddResult = userManager.AddToRoleAsync(user, role.Name).Result;

            Console.WriteLine($"Admin user information:");
            Console.WriteLine($"UserName: {user.UserName}");
            Console.WriteLine($"Password: {password}");
        }
    }
}
