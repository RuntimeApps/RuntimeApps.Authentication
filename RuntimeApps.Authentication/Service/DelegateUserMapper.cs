using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Service {
    /// <summary>
    /// <see cref="IUserMapper{TUser, TUserDto}"/> backed by two delegates.
    /// Used by the <c>AddUserMapper(toDto, toUser)</c> registration overload.
    /// </summary>
    public sealed class DelegateUserMapper<TUser, TUserDto>: IUserMapper<TUser, TUserDto>
        where TUser : class
        where TUserDto : class {
        private readonly Func<TUser, TUserDto> _toDto;
        private readonly Func<TUserDto, TUser> _toUser;

        public DelegateUserMapper(Func<TUser, TUserDto> toDto, Func<TUserDto, TUser> toUser) {
            ArgumentNullException.ThrowIfNull(toDto);
            ArgumentNullException.ThrowIfNull(toUser);
            _toDto = toDto;
            _toUser = toUser;
        }

        public TUserDto ToDto(TUser user) => _toDto(user);

        public TUser ToUser(TUserDto dto) => _toUser(dto);
    }
}
