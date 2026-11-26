using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using RuntimeApps.Authentication.Sample.CookieAuthentication;

#nullable disable

namespace RuntimeApps.Authentication.Sample.CookieAuthentication.Migrations {
    /// <summary>
    /// Adds the absolute session expiry column and the RevokedAt index used by refresh-token cleanup.
    /// This is the change an application that already created the refresh-token table needs to apply.
    /// </summary>
    [DbContext(typeof(ApplicationDbContext))]
    [Migration("20261125230000_AddRefreshTokenSessionHardening")]
    public partial class AddRefreshTokenSessionHardening : Migration {
        protected override void Up(MigrationBuilder migrationBuilder) {
            // The default of 0 means "already expired", so a row that is not backfilled can never be refreshed.
            migrationBuilder.AddColumn<long>(
                name: "AbsoluteExpiresAt",
                table: "AuthenticationRefreshTokens",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            // Existing sessions end no later than the token they currently hold. This copies the stored value
            // as-is, so both columns use the same encoding. Without this step existing sessions are rejected
            // and those users sign in again.
            migrationBuilder.Sql("UPDATE [AuthenticationRefreshTokens] SET [AbsoluteExpiresAt] = [ExpiresAt]");

            migrationBuilder.CreateIndex(
                name: "IX_AuthenticationRefreshTokens_RevokedAt",
                table: "AuthenticationRefreshTokens",
                column: "RevokedAt");
        }

        protected override void Down(MigrationBuilder migrationBuilder) {
            migrationBuilder.DropIndex(
                name: "IX_AuthenticationRefreshTokens_RevokedAt",
                table: "AuthenticationRefreshTokens");

            migrationBuilder.DropColumn(
                name: "AbsoluteExpiresAt",
                table: "AuthenticationRefreshTokens");
        }
    }
}
