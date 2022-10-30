using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace RuntimeApps.Authentication.Sample.CustomModel {
    public class ApplicationDbContext: IdentityDbContext<User, Role, int> {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }
    }
}
