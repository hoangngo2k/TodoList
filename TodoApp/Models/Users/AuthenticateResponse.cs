using TodoApp.Entities;

namespace TodoApp.Models.Users
{
    public class AuthenticateResponse
    {
        public int Id { get; set; }
        public string FullName { get; set; }
        public string UserName { get; set; }
        public Role Role { get; set; }
        public string Token { get; set; }

        public AuthenticateResponse(User user, string token)
        {
            Id = user.Id;
            FullName = user.FullName;
            UserName = user.Username;
            Role = user.Role;
            Token = token;
        }
    }
}
