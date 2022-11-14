# Role Aithorization Sample

This sample shows how to manage user roles and add role authorization to the system. Three roles has been defined with the name of `UserManager`, `UserViewer` and `OtherRole`. In this sample only the users that have `UserManager` role can create users, this feature implemented by overriding `RegisterUser` function in [`AccountController`](./Controllers/AccountController.cs). Also, `UserViewer` can view user info while `OtherRole` do not have any access to user controller. 

ASP.Net core has deferent ways to manage authorization and one of them is [Role-based authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/roles). Also, ASP.Net core identity handels role managements, so all roles will be added to the token and you need only activate authorization by `builder.Services.AddAuthorization();`.

## Controller Actions

There is the controllers that has been defined to manage users and roles.

Controller | Base Controller | Description
--- | --- | ---
[AccountController](./Controllers/AccountController.cs) | `BaseAccountController` | Manage user account actions. In this sample create account overrided to access only by users that have `UserManager` role.
[RoleController](./Controllers/RoleController.cs) | `BaseRoleController` | Manage roles of system. In this sample roles are static and added on initialize database, so the create/update/delete function overrided to response as not implemented
[UserController](./Controllers/UserController.cs) | `BaseUserController` | Manage users of system. This controller has actions of admin or UserManager roles need. Each role that need to view user information should authorzie to this controller.
[UserRoleController](./Controllers/UserRoleController.cs) | `BaseUserRoleController` | Manage user roles. This controller has actions of managing user roles. Each role that needs to manage user roles should authorize in this controller.
