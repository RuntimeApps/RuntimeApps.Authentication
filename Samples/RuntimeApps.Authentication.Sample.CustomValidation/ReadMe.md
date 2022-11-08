# Custom validation sample
Asp.Net core identity implemets useful user, role and password validations which is configurable. Also, you could implement your own validation and add it to the validations, This sample shows how to use .Net validation and how to add new custom one.

## Validation interfaces
If you want add your custom validation, you should implement the interface. You could implement as much as you want and add them to the DI. The ASP.Net core identity manager call all of the implementations and validate the data. If any of them has error, the preocss return the error.

There is the list of validation interfaces

Interface | Description
--- | ---
IUserValidator | Validate the user model when the user is adding the user to system
IPasswordValidator | Validate the password when user is registering password
IRoleValidator | Validate the role when the role is adding to system 

## Asp.Net core Identity validator
Asp.net core identity implements validator which is useable for must cases and it is configurable. You could find all options in [this link](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration). 