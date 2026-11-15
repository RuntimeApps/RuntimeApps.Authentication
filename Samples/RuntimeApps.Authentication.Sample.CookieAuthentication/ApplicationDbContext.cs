using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.EF.Extensions;

namespace RuntimeApps.Authentication.Sample.CookieAuthentication {
    public class ApplicationDbContext: IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int> {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder) {
            base.OnModelCreating(modelBuilder);
            modelBuilder.AddRefreshTokenEntity<int>();
        }
    }
}
