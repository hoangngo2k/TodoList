using Microsoft.EntityFrameworkCore;
using TodoApp.Entities;
using TodoApp.Helpers;

namespace TodoApp.Services
{
    public interface ITodoService
    {
        IEnumerable<Todo> GetAll();
        Todo GetById(int id);
        Todo Create(Todo todo);
        void Update(int id, Todo todo);
        int Delete(int id);
        bool Exists(int id);
        IEnumerable<Todo> FilterDateFromTo(DateTime dateFrom, DateTime dateTo);
    }

    public class TodoService : ITodoService
    {
        private readonly DataContext _context;

        public TodoService(DataContext context)
        {
            _context = context;
        }

        public Todo Create(Todo todo)
        {
            _context.Todos.Add(todo);
            _context.SaveChanges();
            return todo;    
            
        }

        public int Delete(int id)
        {
            _context.Todos.Remove(GetById(id));
            _context.SaveChanges();
            return -1;
        }

        public bool Exists(int id)
        {
            return _context.Todos.Any(t => t.Id == id);
        }

        public IEnumerable<Todo> FilterDateFromTo(DateTime dateFrom, DateTime dateTo)
        {
            return _context.Todos.TemporalBetween(dateFrom, dateTo);
        }

        public IEnumerable<Todo> GetAll()
        {                        
            return _context.Todos;
        }

        public Todo GetById(int id)
        {
            return _context.Todos.Find(id);
        }

        public void Update(int id, Todo todo)
        {
            _context.Entry(todo).State = EntityState.Modified; 
            _context.SaveChanges();                        
        } 
        
        
    }
}
