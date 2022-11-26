using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace RuntimeApps.Authentication.Sample.CustomClaim {
    public class ApplicationDbContext: IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int> {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }
    }
}
