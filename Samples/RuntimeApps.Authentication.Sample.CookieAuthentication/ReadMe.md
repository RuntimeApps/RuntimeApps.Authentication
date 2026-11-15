# Cookie Authentication Sample

This sample demonstrates cookie authentication with optional refresh-token management.

The sample enables refresh tokens explicitly with `AddRefreshToken()` and registers the EF store with SQL Server. Its DbContext includes the refresh-token entity configuration. Run the EF Core migration for the sample database before using the refresh endpoints.

```cs
.AddEfRefreshTokenStore<ApplicationDbContext, IdentityUser<int>, IdentityRole<int>, int>()
.AddRefreshToken(options => {
    options.TokenLifetime = TimeSpan.FromDays(30);
    options.RevokeFamilyOnReuse = true;
})
```

The `MapLoginApi` extension automatically maps `POST /api/refresh`, `POST /api/logout`, and the authenticated `POST /api/logout/all` endpoints when refresh-token support is enabled. Cookie refresh credentials are stored in a Secure, HttpOnly cookie. For cross-origin clients, configure the exact allowed origins and review the application's CORS and CSRF policy.

Each successful login creates an independent session. Refresh-token reuse revokes only the affected session family; logout-all revokes all sessions for the authenticated user.

Applications that do not call `AddRefreshToken()` retain the existing cookie authentication behavior and do not need the refresh-token entity.
