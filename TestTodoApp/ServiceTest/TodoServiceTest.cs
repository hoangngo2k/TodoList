using Microsoft.Data.SqlClient.Server;
using Microsoft.EntityFrameworkCore;
using MockQueryable.Moq;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TestTodoApp.ServiceFakes;
using TodoApp.Entities;
using TodoApp.Helpers;
using TodoApp.Services;

namespace TestTodoApp.ServiceTest
{
    public class TodoServiceTest
    {
        private readonly Mock<DataContext> _context;
        private readonly TodoService service;
        private MockDatas data;
        private IEnumerable<Todo> todos;

        public TodoServiceTest()
        {
            var options = new DbContextOptions<DataContext>();
            _context = new Mock<DataContext>(options);
            service = new TodoService(_context.Object);
            data = new MockDatas();            
        }

        [Fact]
        public void GetAll_ReturnsTodos()
        {
            var mockDbSet = data.GetAll().AsQueryable().BuildMockDbSet();
            _context.Setup(c => c.Todos).Returns(mockDbSet.Object);

            var result = service.GetAll();
            
            Assert.Equal(data.GetAll().Count(), result.Count());
        }

        [Fact]
        public void GetAll_ReturnsNoTodo()
        {
            var mockDbSet = new List<Todo>().AsQueryable().BuildMockDbSet();
            _context.Setup(c => c.Todos).Returns(mockDbSet.Object);

            var result = service.GetAll();

            Assert.Equal(0, result.Count());
        }

        [Theory]
        [InlineData(1)]
        public void GetById_ReturnsTodo(int id)
        {
            var todo = new Todo
            {
                Id = 1,
                Title = "CV1",
                Tag = "Work",
                Description = "Try hard",
                CreatedDate = DateTime.Now
            };
            var todos = new List<Todo> { todo };
            var mockDbSet = todos.AsQueryable().BuildMockDbSet();
            _context.SetupGet(c => c.Todos).Returns(mockDbSet.Object);

            var result = service.GetById(id);

            Assert.NotNull(result);
            Assert.Equal(id, result.Id);
        }              
    }
}
