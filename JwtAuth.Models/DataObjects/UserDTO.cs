namespace JwtAuth.Models
{
    public class UserDTO
    {
        public string username { get; set; } = string.Empty;
        public string password { get; set; } = string.Empty;
        public string role { get; set; } = string.Empty;
    }
}
