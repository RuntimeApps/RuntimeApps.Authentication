# Custom store sample
This sample implements the stores as a in-memory store which the userName and roleName are the id of models. Based on this example you could implement your own store for your database or your ORM like Dapper.

This example use Asp.Net core identity store. So the implementations could be used in other Identity services like IdentityServer V4. Also, There is lots of implemetation of this store in other databases, so you could use them too.

## Store implementations
The classes that should be implemented for user identity store are:

Store Class | Base Class | Description
--- | --- | ---
[UserStore](./Store/CustomUserStore.cs) | UserStoreBase | Implement user store interfaces. Some of the functions are implemented in `UserStoreBase` but others should be implemented. If you want to use Entity Framework core and change some implementation, You should inhareant `UserStore` class which implement that functions and overide your functions. 
[RoleStore](./Store/CustomRoleStore.cs) | RoleStoreBase | Implement role store interfaces. Some of the functions are implemented in `RoleStoreBase` but others should be implemented. If you want to use Entity Framework core and change some implementation, You should inhareant `RoleStore` class which implement that functions and overide your functions.

## Custom model store
if you have your own user model which is not inharent from `IdentityUser`, You should implement all of user store interfaces. There is the list of interfaces that should be implemented:

- UserStore
    - IUserStore
    - IUserLoginStore
    - IUserClaimStore
    - IUserPasswordStore
    - IUserSecurityStampStore
    - IUserEmailStore
    - IUserLockoutStore
    - IUserPhoneNumberStore
    - IQueryableUserStore
    - IUserTwoFactorStore
    - IUserAuthenticationTokenStore
    - IUserAuthenticatorKeyStore
    - IUserTwoFactorRecoveryCodeStore
    - IUserRoleStore
    - IProtectedUserStore
- RoleStore
    - IRoleStore
    - IRoleClaimStore

**Note:** If you don't use some features, you could avoid implemeting them. But the `IUserStore` and `IRoleStore` is required.
