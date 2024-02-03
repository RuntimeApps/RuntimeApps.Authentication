# Claim Authorization Sample

This sample shows how to manage roles, role claims, user roles and user claims. In this sample `UserManager` claim has been defined to users want to have access user manager parts. `UserManager` claim type has 5 deferent value which is shown as a number. There is the list of claim values that has been defined for `UserManager` claim type:

```cs
public static ClaimData UserManagerClaim { get; } = new ClaimData("UserManager", "Claims of users access to managing users", new Dictionary<string, string>() {
                { "1", "View users info" },
                { "2", "Manage users data" },
                { "3", "Manage users roles" },
                { "4", "Manage role infos" },
                { "5", "Manage role claims" },
            });
```

In this sample each claim value has all permisions before there number. For example, if a user has `UserManager` claim with value of 3, user can view, manage users and user roles but he cannot manage roles and role claims. These defenition has been defined in [PolicyConsts](./PolicyConsts.cs) class. You can use your own palicy and claim defenition based in your need.

In Asp.Net core identity users can have claims as same as roles. So each user has sum of own claims and role claims which will be added to created jwt token. 

## Controller Actions

RuntimeApps.Authentication library implements controllers that might be needed in user managements. You could add each controller to your solution by implemeting them as base class.

Controller | Base Controller | Description
--- | --- | ---
[UserController](./Controllers/UserController.cs) | `BaseUserController` | Manage users of system. This user return user information by their id or username. In this sample the users that have `UserManager` claim with value 1 (ViewUser) or higher can access this controller actions.
[UserRoleController](./Controllers/UserRoleController.cs) | `BaseUserRoleController` | Manage user roles. This controller has actions of managing user roles. In this sample the users that have `UserManager` claim with value 3 (ManageUserRoles) or higher can access this controller actions.
[UserClaimController](./Controllers/UserClaimController.cs) | `BaseUserClaimController` | Manage user claims. Claim can be added to user by this controller. In this sample the users that have `UserManager` claim with value 3 (ManageUserRoles) or higher can access this controller actions.
[RoleController](./Controllers/RoleController.cs) | `BaseRoleController` | Manage roles of system. In this sample users that have `UserManager` claim with value 4 (ManageRoles) or higher can access this controller actions.
[RoleClaimController](./Controllers/RoleClaimController.cs) | `BaseRoleClaimController` | Manage role claims. In this sample users that have `UserManager` claim with value 5 (ManageRoleClaims) can access this controller actions.
[ClaimController](./Controllers/ClaimController.cs) | | Claim defenition in this sample is static, so a controller has been implemented to show the claim defenition to the API caller.
