using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace TodoApp.Entities
{
    public class User
    {
        [Key]
        public int Id { get; set; }
        [Required]
        public string FullName { get; set; }
        public string Username { get; set; }
        [JsonIgnore]
        public string Password { get; set; }
        public Role Role { get; set; }
    }
}
