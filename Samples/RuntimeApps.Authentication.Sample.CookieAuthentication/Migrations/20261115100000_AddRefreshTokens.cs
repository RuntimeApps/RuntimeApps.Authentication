using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using RuntimeApps.Authentication.Sample.CookieAuthentication;

#nullable disable

namespace RuntimeApps.Authentication.Sample.CookieAuthentication.Migrations {
    [DbContext(typeof(ApplicationDbContext))]
    [Migration("20261115100000_AddRefreshTokens")]
    public partial class AddRefreshTokens : Migration {
        protected override void Up(MigrationBuilder migrationBuilder) {
            migrationBuilder.CreateTable(
                name: "AuthenticationRefreshTokens",
                columns: table => new {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<int>(type: "int", nullable: false),
                    FamilyId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    ExpiresAt = table.Column<long>(type: "bigint", nullable: false),
                    RevokedAt = table.Column<long>(type: "bigint", nullable: true),
                    ReplacedByTokenId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    SessionName = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true)
                },
                constraints: table => {
                    table.PrimaryKey("PK_AuthenticationRefreshTokens", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuthenticationRefreshTokens_TokenHash",
                table: "AuthenticationRefreshTokens",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuthenticationRefreshTokens_UserId_FamilyId",
                table: "AuthenticationRefreshTokens",
                columns: new[] { "UserId", "FamilyId" });

            migrationBuilder.CreateIndex(
                name: "IX_AuthenticationRefreshTokens_UserId_RevokedAt",
                table: "AuthenticationRefreshTokens",
                columns: new[] { "UserId", "RevokedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_AuthenticationRefreshTokens_FamilyId_RevokedAt",
                table: "AuthenticationRefreshTokens",
                columns: new[] { "FamilyId", "RevokedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_AuthenticationRefreshTokens_ExpiresAt",
                table: "AuthenticationRefreshTokens",
                column: "ExpiresAt");
        }

        protected override void Down(MigrationBuilder migrationBuilder) {
            migrationBuilder.DropTable(name: "AuthenticationRefreshTokens");
        }
    }
}