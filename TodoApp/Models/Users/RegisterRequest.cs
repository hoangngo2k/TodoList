using System.ComponentModel.DataAnnotations;

namespace TodoApp.Models.Users
{
    public class RegisterRequest
    {
        [Required(ErrorMessage = "Username is required")]
        public string UserName { get; set; }
        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }
        [Required(ErrorMessage = "Email is required")]
        public string FullName { get; set; }
    }
}
