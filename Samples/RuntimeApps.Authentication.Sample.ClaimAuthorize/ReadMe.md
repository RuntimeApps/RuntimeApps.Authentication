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

```cs

app.MapGroup("api")
    .WithTags("Authentication APIs")
    .MapLoginApi<IdentityUser<int>, IdentityUserDto<int>, int>()
    .MapRegisterApi<IdentityUser<int>, IdentityUserDto<int>, int>();

app.MapGroup("api/account")
    .WithTags("Account APIs")
    .MapAccountApi<IdentityUser<int>, IdentityUserDto<int>, int>();

app.MapGroup("api/user")
    .WithTags("User View")
    .RequireAuthorization(PolicyConsts.ViewUserPolicy)
    .MapUserGetApi<IdentityUser<int>, IdentityUserDto<int>>();

app.MapGroup("api/user")
    .WithTags("User Manage")
    .RequireAuthorization(PolicyConsts.ManageUserRolePolicy)
    .MapUserClaimGetApi<IdentityUser<int>>()
    .MapUserClaimManageApi<IdentityUser<int>>()
    .MapUserRoleGetApi<IdentityUser<int>>()
    .MapUserRoleManageApi<IdentityUser<int>>();

app.MapGroup("api/role")
    .WithTags("Role Claim")
    .RequireAuthorization(PolicyConsts.ManageRoleClaimPolicy)
    .MapRoleClaimGetApi<IdentityRole<int>>()
    .MapRoleClaimManageApi<IdentityRole<int>>();

app.MapGroup("api/role")
    .WithTags("Role")
    .RequireAuthorization(PolicyConsts.ManageRolePolicy)
    .MapRoleGetApi<IdentityRole<int>>()
    .MapRoleManageApi<IdentityRole<int>>();

app.MapGet("api/claim", () => ClaimConsts.GetAllClaimData());

```
