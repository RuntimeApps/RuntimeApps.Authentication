using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Service {
    public class JwtProvider<TUser, TKey>: IJwtProvider<TUser>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey> {
        private readonly JwtBearerOptions _jwtOption;

        public JwtProvider(IOptions<JwtBearerOptions> options) {
            _jwtOption = options.Value;
        }
        public Token GenerateToken(TUser user) {
            var credential = new SigningCredentials(_jwtOption.TokenValidationParameters.IssuerSigningKey, SecurityAlgorithms.HmacSha256);

            var claims = new[] {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Email, user.Email),
                };

            DateTime expire = DateTime.Now.AddMinutes(10);
            var token = new JwtSecurityToken(_jwtOption.TokenValidationParameters.ValidIssuer, _jwtOption.Audience,
                claims,
                expires: expire,
                signingCredentials: credential
                );
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            return new Token() {
                AuthenticationToken = tokenString,
                ExpireDate = expire
            };
        }

        public int? ValidateToken(string token) {
            if(token == null)
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();
            try {
                tokenHandler.ValidateToken(token, new TokenValidationParameters {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = _jwtOption.TokenValidationParameters.IssuerSigningKey,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var userId = int.Parse(jwtToken.Claims.First(x => x.Type == "Email").Value);
                return userId;
            } catch {
                return null;
            }
        }
    }
}
