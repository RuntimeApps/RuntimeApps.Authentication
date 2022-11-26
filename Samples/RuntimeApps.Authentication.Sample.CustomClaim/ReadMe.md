# Customize jwt claim

Asp.Net identity handels claim of generated token. It adds needed claims with standard types. There is two implementation of token claim generator in ASP.Net identity. 

* **UserClaimsPrincipalFactory<TUser>**: This class generated basic user claims. The list of claims are:

    * **UserId**

    * **UserName**

    * **Email**: if UserStore implementes `IUserEmailStore` and user has email.

    * **SecurityStamp**: if UserStore implementes ``IUserSecurityStampStore`.

    * **UserClaim**: if UserStore implementes `IUserClaimStore` and user has custom claim.

* **UserClaimsPrincipalFactory<TUser, TRole>** : This class inharient `UserClaimsPrincipalFactory<TUser>` and generate role claims:

    * **Role**: if UserStore implements `IUserRoleStore` and user has roles.

    * **RoleClaim**: RoleStore implemets `IRoleClaimStore` and roles have claims.

If you want more claims or some claims should be changed you shoul implement `IUserClaimsPrincipalFactory` or inharent one of implementations and add you custom claims. Finaly you should add your implementation to DI for this interface implementation.

This example shows how to add mobile phone to claims. The generated token has all of default claims and MobilePhone claim.

One of usage of this approach is that you can add user age to claims and make Authorize base on user ages.
