using System.ComponentModel.DataAnnotations;

namespace TodoApp.Entities
{
    public class Todo
    {
        [Key]
        public int Id { get; set; }
        [Required]
        public string Title { get; set; }
        [Required]
        public string Tag { get; set; }
        [Required]
        public string Description { get; set; }
        [Required]
        public DateTime CreatedDate { get; set;}
    }
}
