using System.ComponentModel.DataAnnotations;

namespace TodoApp.Models.Users
{
    public class AuthenticateRequest
    {
        [Required(ErrorMessage = "Username is required")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

        public AuthenticateRequest() { }
    }
}
