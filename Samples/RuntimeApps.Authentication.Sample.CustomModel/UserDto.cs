using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Sample.CustomModel {
    public class UserDto: IdentityUserDto<int> {
        public string Name { get; set; }
        public string ProfilePicture { get; set; }
    }
}