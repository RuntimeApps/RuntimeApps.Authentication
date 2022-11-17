# Cookie Authentication Sample

This example showes how to save authentication in cookie and handel it by cookie.

The only thing that should be done is that insted of `UserJwt()` add Cookie to authentication builder like blow code:

```cs
.AddCookie(JwtBearerDefaults.AuthenticationScheme)
```
