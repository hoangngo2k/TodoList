using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TodoApp.Entities;
using TodoApp.Services;

namespace TestTodoApp.ServiceFakes
{
    public class MockDatas : ITodoService
    {
        private readonly List<Todo> _todoList;

        public MockDatas()
        {
            _todoList = new List<Todo>
            {
                new Todo
                {
                    Id = 1,
                    Title = "CV1",
                    Tag = "Work",
                    Description = "Try hard",
                    CreatedDate = DateTime.Now
                },
                new Todo
                {
                    Id = 2,
                    Title = "CV2",
                    Tag = "Work",
                    Description = "Try hard",
                    CreatedDate = DateTime.Now
                },
                new Todo
                {
                    Id = 3,
                    Title = "CV3",
                    Tag = "Work",
                    Description = "Try hard",
                    CreatedDate = DateTime.Now
                },
                new Todo
                {
                    Id = 4,
                    Title = "Camping",
                    Tag = "Family",
                    Description = "Happy",
                    CreatedDate = DateTime.Now
                },
                new Todo
                {
                    Id = 5,
                    Title = "Drink coffe",
                    Tag = "Friend",
                    Description = "Happy",
                    CreatedDate = DateTime.Now
                }
            };
        }

        public Todo Create(Todo todo)
        {
            _todoList.Add(todo);
            return todo;
        }

        public int Delete(int id)
        {
            var todo = GetById(id);
            _todoList.Remove(todo);
            return -1;
        }

        public bool Exists(int id)
        {
            return _todoList.Any(t => t.Id == id);
        }

        public IEnumerable<Todo> FilterDateFromTo(DateTime dateFrom, DateTime dateTo)
        {
            return null;
        }

        public IEnumerable<Todo> GetAll()
        {
            return _todoList;
        }

        public Todo GetById(int id)
        {
            return _todoList.FirstOrDefault(t => t.Id == id);
        }

        public void Update(int id, Todo todo)
        {
            var oldTodo = GetById(id);
            oldTodo.Title = todo.Title;
            oldTodo.Tag = todo.Tag;
            oldTodo.Description = todo.Description;
            oldTodo.CreatedDate = todo.CreatedDate;            
        }
    }
}
