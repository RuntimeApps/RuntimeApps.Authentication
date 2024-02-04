# Role Aithorization Sample

This sample shows how to manage user roles and add role authorization to the system. Three roles has been defined with the name of `UserManager`, `UserViewer` and `OtherRole`. In this sample only the users that have `UserManager` role can create users. Also, `UserViewer` can view user info while `OtherRole` do not have any access to user controller. 

ASP.Net core has deferent ways to manage authorization and one of them is [Role-based authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/roles). Also, ASP.Net core identity handels role managements, so all roles will be added to the token and you need only activate authorization by `builder.Services.AddAuthorization();`.

```cs

app.MapGroup("api")
    .WithTags("Authentication APIs")
    .MapLoginApi<IdentityUser<int>, IdentityUserDto<int>, int>();

app.MapGroup("api/account")
    .WithTags("Account APIs")
    .MapAccountApi<IdentityUser<int>, IdentityUserDto<int>, int>();

app.MapGroup("api/user")
    .WithTags("User View")
    .RequireAuthorization(config => config.RequireRole(RoleConsts.UserViewRole, RoleConsts.UserManagerRole))
    .MapUserGetApi<IdentityUser<int>, IdentityUserDto<int>>();

app.MapGroup("api/role")
    .WithTags("Role View")
    .RequireAuthorization(config => config.RequireRole(RoleConsts.UserViewRole, RoleConsts.UserManagerRole))
    .MapRoleGetApi<IdentityRole<int>>();

app.MapGroup("api/user")
    .WithTags("User Manage")
    .RequireAuthorization(config => config.RequireRole(RoleConsts.UserManagerRole))
    .MapRegisterApi<IdentityUser<int>, IdentityUserDto<int>, int>()
    .MapUserRoleGetApi<IdentityUser<int>>()
    .MapUserRoleManageApi<IdentityUser<int>>();

```
