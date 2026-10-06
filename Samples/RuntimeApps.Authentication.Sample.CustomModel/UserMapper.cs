using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Sample.CustomModel {
    public class UserMapper: IUserMapper<User, UserDto> {
        public UserDto ToDto(User user) {
            // Return null if input is null to mirror common mapper behavior.
            if(user == null) return null;

            // Map simple properties from the domain model to the DTO.
            return new UserDto {
                Id = user.Id,
                UserName = user.UserName,
                Name = user.Name,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                TwoFactorEnabled = user.TwoFactorEnabled,
                ProfilePicture = user.ProfilePicture,
            };
        }
        public User ToUser(UserDto dto) {
            if(dto is null)
                throw new ArgumentNullException(nameof(dto));

            // Map properties from the DTO to a new User instance.
            return new User {
                Id = dto.Id,
                UserName = dto.UserName,
                Name = dto.Name,
                Email = dto.Email,
                PhoneNumber = dto.PhoneNumber,
                TwoFactorEnabled = dto.TwoFactorEnabled,
                ProfilePicture = dto.ProfilePicture
            };
        }
    }
}
