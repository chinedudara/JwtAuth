using JwtAuth.Models;

namespace JwtAuth.Services.IServices
{
    public interface IAuthService
    {
        Task<string> LoginUser(string username, string password);
        Task<UserDTO> CreateUser(UserDTO user);

        Task<List<User>> GetAll();
    }
}
