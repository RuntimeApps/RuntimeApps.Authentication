using AutoMapper;
using Microsoft.AspNetCore.Identity;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Extensions {
    public class IdentityUserMapper<TUser, TUserDto, TKey>: Profile
        where TUser : IdentityUser<TKey>
        where TUserDto : IdentityUserDto<TKey>
        where TKey : IEquatable<TKey> {

        public IdentityUserMapper() {
            UserToDtoConfig = base.CreateMap<TUser, TUserDto>();

            DtoToUserConfig = base.CreateMap<TUserDto, TUser>();
        }

        protected virtual IMappingExpression<TUser, TUserDto> UserToDtoConfig { get; set; }
        protected virtual IMappingExpression<TUserDto, TUser> DtoToUserConfig { get; set; }
    }
}
