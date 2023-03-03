using Microsoft.EntityFrameworkCore;
using TodoApp.Entities;

namespace TodoApp.Helpers
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions<DataContext> options) : base(options) { }

        public virtual DbSet<User> Users { get; set; } 
        public virtual DbSet<Todo> Todos { get; set; }
    }
}
