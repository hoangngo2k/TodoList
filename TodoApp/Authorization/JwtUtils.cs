using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using TodoApp.Entities;
using TodoApp.Helpers;

namespace TodoApp.Authorization
{
    public interface IJwtUtils
    {
        string GenerateJwtToken(User user);
        int? ValidateToken(string token);
        RefreshToken GenerateRefreshToken(string ipAdress);
    }

    public class JwtUtils : IJwtUtils
    {
        private readonly AppSettings _settings;
        private readonly DataContext _context;

        public JwtUtils(IOptions<AppSettings> settings, DataContext context)
        {
            _settings = settings.Value;
            _context = context;
        }

        public string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_settings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("id", user.Id.ToString())
                }),
                Expires = DateTime.UtcNow.AddMinutes(60),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public RefreshToken GenerateRefreshToken(string ipAdress)
        {
            var refreshToken = new RefreshToken
            {
                Token = getUniqueToken(),
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAdress,                
            };

            return refreshToken;

            string getUniqueToken()
            {
                var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

                var tokenIsUnique = !_context.Users.Any(u => u.RefreshTokens.Any(r => r.Token == token));

                if (!tokenIsUnique)
                {
                    return getUniqueToken();
                }

                return token;
            }
        }

        public int? ValidateToken(string token)
        {
            if(token == null)
            {
                return null;
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_settings.Secret);
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var id = int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);
                return id;
            }
            catch
            {
                return null;
            }
        }
    }
}
