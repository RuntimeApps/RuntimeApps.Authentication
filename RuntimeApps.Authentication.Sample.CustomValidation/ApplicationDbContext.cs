using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace RuntimeApps.Authentication.Sample.CustomValidation {
    public class ApplicationDbContext: IdentityDbContext<IdentityUser, IdentityRole, string> {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }
    }
}
