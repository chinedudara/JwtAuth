using JwtAuth.Infrastructure.EFCore;
using JwtAuth.Models;
using JwtAuth.Services.IServices;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtAuth.Services
{
    public class AuthService : IAuthService
    {
        private readonly IConfiguration _config;
        private readonly IHttpContextAccessor _httpContext;
        private readonly AppDbContext _context;
        private readonly string _token;

        public AuthService(IConfiguration config, IHttpContextAccessor httpContext, AppDbContext context)
        {
            _config = config;
            _httpContext = httpContext;
            _context = context;
            _token = config.GetSection("Keys:TokenSecret").Value;
        }

        public async Task<string> LoginUser(string username, string password)
        {
            try
            {
                var user = await _context.users.FirstOrDefaultAsync(x => x.Username == username);
                if (user == null) return "User not found";

                if (!VerifyHash(password, user.PasswordHash, user.PasswordSalt))
                    return "Invalid password";

                var token = GenerateToken(user);
                return token;
            }
            catch (Exception ex)
            {

                throw;
            }
        }

        public async Task<UserDTO> CreateUser(UserDTO user)
        {
            try
            {
                if (_context.users.Any(x => x.Username == user.username)) return null;

                CreateHash(user.password, out byte[] passwordHash, out byte[] passwordSalt);
                User userObj = new User
                {
                    PasswordHash = passwordHash,
                    PasswordSalt = passwordSalt,
                    Username = user.username,
                    Role = user.role,
                };
                await _context.users.AddAsync(userObj);
                var res = _context.SaveChanges();
                if (res !> 0)
                {
                    return null;
                }

                return user;
            }
            catch (Exception ex)
            {

                throw;
            }
        }

        public async Task<List<User>> GetAll()
        {
            return await _context.users.ToListAsync();
        }

        private void CreateHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var hsh = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return passwordHash.SequenceEqual(hsh);
            }
        }

        private string GenerateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_token));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
    }
}