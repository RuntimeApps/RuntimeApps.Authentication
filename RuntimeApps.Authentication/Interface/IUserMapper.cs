namespace RuntimeApps.Authentication.Interface {
    /// <summary>
    /// Maps between the identity user entity and the DTO exposed by the API endpoints.
    /// Implement it with any mapping approach (hand-written, Mapperly, Mapster, AutoMapper, ...)
    /// and register it with <c>AddUserMapper</c>.
    /// </summary>
    public interface IUserMapper<TUser, TUserDto>
        where TUser : class
        where TUserDto : class {
        /// <summary>Entity to DTO. Used by the login, register, account and user-get endpoints.</summary>
        TUserDto ToDto(TUser user);

        /// <summary>DTO to entity. Used by the register endpoint only.</summary>
        TUser ToUser(TUserDto dto);
    }
}
