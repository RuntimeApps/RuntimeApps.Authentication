# Custom identity user model sample
This sample costomize user and role model in ASP.Net core identity application. The only thing is that the user models should inhareant base models. There is the list of base models that could be used:

Model | Base Class | Description
--- | --- | ---
User | IdentityUser | This model has user information. Basic user information like `UserName`, `Email` and etc exist in base model and you could add more fileds to user model. Also you could map these fields from extrenal login by configuration of it.
UserDto | IdentityUserDto | This model introduce the fields that response in APIs. If you have some fields that have deferent name in `User` and `UserDto`, You should implement your own mapper profile which inharent `IdentityUserMapper`.
Role | IdentityRole | This model has role information. You could costomize it by your own.

## Custom model without inharent
if you want to use costom user model without inharent `IdentityUser`, you should implement all of user store interfaces. The needed implementation and sample are in [this sample](../RuntimeApps.Authentication.Sample.CustomStore/).