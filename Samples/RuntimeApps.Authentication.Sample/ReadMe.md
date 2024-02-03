# Basic user manager sample
The basic user manager implementation of RuntimeApps.Authentication. This sample Uses `int` as key of user models.

In this sample, the usage of exterrnal login is provided. So you can configure your own external login and use it.

## File descriptions

File | Usage 
--- | ---
[ApplicationDbContext](./ApplicationDbContext.cs) | The Entity Framework core Db Context in the application. It inharients `IdentityDbContext` which is default implemetation of ASP.net core identity in Entity framework core. You could costomize the tables and add your tables in this file.
[Program](./Program.cs) | The main configuration of asp.net core application. You should add commented codes to your project.
