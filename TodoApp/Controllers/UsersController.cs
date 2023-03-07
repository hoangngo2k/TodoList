using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using TodoApp.Authorization;
using TodoApp.Entities;
using TodoApp.Helpers;
using TodoApp.Models.Users;
using TodoApp.Services;

namespace TodoApp.Controllers
{    
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {        
        private IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public IActionResult Authenticate(AuthenticateRequest request)
        {
            var response = _userService.Authenticate(request, ipAddress());
            setTokenCookie(response.RefreshToken);
            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public IActionResult RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var response = _userService.RefreshToken(refreshToken, ipAddress());
            setTokenCookie(response.RefreshToken);
            return Ok(response);
        }

        [HttpPost("revoke-token")]
        public IActionResult RevokeToken(RevokeTokenRequest request)
        {
            var token = request.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
            {
                return BadRequest(new { message = "Token is required" });
            }

            _userService.RevokeToken(token, ipAddress());
            return Ok(new { message = "Token revoked" });
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public IActionResult Register(RegisterRequest request)
        {
            _userService.Register(request);
            return Ok(new { message = "Registration successful" });
        }

        [Authorize(Role.Admin)]
        [HttpGet]
        public IActionResult Get()
        {
            var users = _userService.GetAll();
            return Ok(users);
        }

        [HttpGet("{id}")]
        public IActionResult GetById(int id)
        {
            var currentUser = (User)HttpContext.Items["User"];
            if(id != currentUser.Id && currentUser.Role != Role.Admin)
            {
                return Unauthorized(new {message = "Unauthorized"});
            }
            var user = _userService.GetById(id);
            return Ok(user);
        }

        [HttpGet("{id}/refresh-tokens")]
        public IActionResult GetRefreshTokens(int id)
        {
            var user = _userService.GetById(id);
            return Ok(user.RefreshTokens);
        }

        [Authorize(Role.Admin)]
        [HttpPut("{id}")]
        public IActionResult Update(int id, UpdateRequest model)
        {
            _userService.Update(id, model);
            return Ok(new { message = "User updated successfully" });
        }

        [Authorize(Role.Admin)]
        [HttpDelete("{id}")]
        public IActionResult Delete(int id)
        {
            _userService.Delete(id);
            return Ok(new { message = "User deleted successfully" });
        }

        private void setTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7)
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }

        private string ipAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }
    }
}
