using Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace RuntimeApps.Authentication.Sample {
    public class ApplicationDbContext: IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int> {

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

    }
}
