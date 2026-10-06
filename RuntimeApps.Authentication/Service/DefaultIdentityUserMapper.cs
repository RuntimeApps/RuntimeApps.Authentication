using Microsoft.AspNetCore.Identity;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Service {
    /// <summary>
    /// Built-in mapper between <see cref="IdentityUser{TKey}"/> and <see cref="IdentityUserDto{TKey}"/>
    /// (or a DTO derived from it). Override the virtual methods to map extra properties.
    /// </summary>
    public class DefaultIdentityUserMapper<TUser, TUserDto, TKey>: IUserMapper<TUser, TUserDto>
        where TUser : IdentityUser<TKey>, new()
        where TUserDto : IdentityUserDto<TKey>, new()
        where TKey : IEquatable<TKey> {

        public virtual TUserDto ToDto(TUser user) {
            ArgumentNullException.ThrowIfNull(user);
            return new TUserDto {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                TwoFactorEnabled = user.TwoFactorEnabled
            };
        }

        /// <remarks>
        /// Id and TwoFactorEnabled are intentionally not copied: this is the registration path, so a client
        /// must not choose its own key or switch on two-factor before an authenticator is set up.
        /// </remarks>
        public virtual TUser ToUser(TUserDto dto) {
            ArgumentNullException.ThrowIfNull(dto);
            return new TUser {
                UserName = dto.UserName,
                Email = dto.Email,
                PhoneNumber = dto.PhoneNumber
            };
        }
    }
}
