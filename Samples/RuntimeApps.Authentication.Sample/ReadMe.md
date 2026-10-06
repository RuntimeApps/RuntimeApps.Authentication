# Basic user manager sample
The basic user manager implementation of RuntimeApps.Authentication. This sample Uses `int` as key of user models.

In this sample, the usage of exterrnal login is provided. So you can configure your own external login and use it.

## File descriptions

File | Usage 
--- | ---
[ApplicationDbContext](./ApplicationDbContext.cs) | The Entity Framework core Db Context in the application. It inharients `IdentityDbContext` which is default implemetation of ASP.net core identity in Entity framework core. You could costomize the tables and add your tables in this file.
[Program](./Program.cs) | The main configuration of asp.net core application. You should add commented codes to your project.


## User mapping

The API endpoints convert between your identity user (`TUser`) and the DTO returned to clients (`TUserDto`)
through one small interface, so the library has no dependency on a mapping library:

```cs
public interface IUserMapper<TUser, TUserDto> {
    TUserDto ToDto(TUser user);   // login, register, account and user-get endpoints
    TUser ToUser(TUserDto dto);   // register endpoint only
}
```

### Out of the box

`IdentityUserDto<TKey>` (and `IdentityUserDto` for string keys) work with no mapper setup. The built-in
`DefaultIdentityUserMapper` copies `Id`, `UserName`, `Email`, `PhoneNumber` and `TwoFactorEnabled` to the DTO.
When registering, it only reads `UserName`, `Email` and `PhoneNumber` from the DTO.

### Your own DTO or mapper

Register a mapper after `AddRuntimeAppsAuthentication`. Registering a mapper for a DTO replaces any earlier one
for that DTO, so the last call wins.

```cs
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddRuntimeAppsAuthentication<AppUser, IdentityRole, string>()
    .AddEfStores<ApplicationDbContext, AppUser, IdentityRole, string>()
    .AddUserMapper<AppUserDto, AppUserMapper>()   // or one of the options below
    ...
```

**Inline delegates**

```cs
.AddUserMapper<AppUserDto>(
    toDto: u => new AppUserDto { Id = u.Id, UserName = u.UserName, Email = u.Email, DisplayName = u.DisplayName },
    toUser: d => new AppUser { UserName = d.UserName, Email = d.Email, DisplayName = d.DisplayName })
```

**Hand-written class**

```cs
public class AppUserMapper : IUserMapper<AppUser, AppUserDto> {
    public AppUserDto ToDto(AppUser u) => new() { Id = u.Id, UserName = u.UserName, Email = u.Email };
    public AppUser ToUser(AppUserDto d) => new() { UserName = d.UserName, Email = d.Email };
}
```

**Mapperly** (source generated, MIT)

```cs
[Mapper]
public partial class AppUserMapper : IUserMapper<AppUser, AppUserDto> {
    public partial AppUserDto ToDto(AppUser user);
    public partial AppUser ToUser(AppUserDto dto);
}
```

**Mapster**

```cs
public class AppUserMapper : IUserMapper<AppUser, AppUserDto> {
    public AppUserDto ToDto(AppUser user) => user.Adapt<AppUserDto>();
    public AppUser ToUser(AppUserDto dto) => dto.Adapt<AppUser>();
}
```

**AutoMapper** (keep using it if you want)

```cs
public class AppUserMapper(IMapper mapper) : IUserMapper<AppUser, AppUserDto> {
    public AppUserDto ToDto(AppUser user) => mapper.Map<AppUserDto>(user);
    public AppUser ToUser(AppUserDto dto) => mapper.Map<AppUser>(dto);
}
```

By default a mapper registered with `AddUserMapper<TUserDto, TMapper>()` is scoped. Pass
`ServiceLifetime.Singleton` for stateless mappers such as Mapperly's.

### Endpoints

Endpoint registration is unchanged apart from the DTO type argument, for example:

```cs
app.MapGroup("api").MapLoginApi<IdentityUser, IdentityUserDto, string>()
                   .MapRegisterApi<IdentityUser, IdentityUserDto, string>();
app.MapGroup("api/account").MapAccountApi<IdentityUser, IdentityUserDto, string>();
```
