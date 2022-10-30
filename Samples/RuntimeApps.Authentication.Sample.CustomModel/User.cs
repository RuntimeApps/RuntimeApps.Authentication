using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Sample.CustomModel {
    public class User: IdentityUser<int> {
        public string Name { get; set; }
        public string ProfilePicture { get; set; }
    }
}
