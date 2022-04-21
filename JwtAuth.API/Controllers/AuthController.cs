using JwtAuth.Models;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuth.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly IAuthService _authService;

        public AuthController(IConfiguration configuration, IAuthService authService)
        {
            _configuration = configuration;
            _authService = authService;
        }

        [HttpGet("/getall")]
        public async Task<ActionResult> GetAllUsers()
        {
            var res = await _authService.GetAll();
            return Ok(res);
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDTO>> Register(UserDTO request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var res = await _authService.CreateUser(request);
            return Ok(res);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDTO request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var res = await _authService.LoginUser(request.username, request.password);
            return Ok(res);
        }

    }
}
