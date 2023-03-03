using Microsoft.AspNetCore.Mvc;
using Moq;
using TodoApp.Controllers;
using TodoApp.Entities;
using TodoApp.Services;

namespace TestTodoApp.ControllersTest
{
    public class TodoControllerTest
    {
        private readonly TodoesController _todoesController;
        private readonly Mock<ITodoService> _mockService;
        private readonly List<Todo> todos;

        public TodoControllerTest()
        {
            _mockService = new Mock<ITodoService>();
            _todoesController = new TodoesController(_mockService.Object);
            todos = new List<Todo>
            {
                new Todo
                {
                    Id = 1,
                    Title = "CV1",
                    Tag = "Work",
                    Description = "Try hard",
                    CreatedDate = DateTime.Now,
                },
                new Todo
                {
                    Id = 2,
                    Title = "CV2",
                    Tag = "Work",
                    Description = "Try hard",
                    CreatedDate = DateTime.Now,
                },
                new Todo
                {
                    Id = 3,
                    Title = "CV3",
                    Tag = "Work",
                    Description = "Try hard",
                    CreatedDate = DateTime.Now,
                },
                new Todo
                {
                    Id = 4,
                    Title = "Camping",
                    Tag = "Family",
                    Description = "Happy",
                    CreatedDate = DateTime.Now,
                },
                new Todo
                {
                    Id = 5,
                    Title = "Drink coffe",
                    Tag = "Friend",
                    Description = "Happy",
                    CreatedDate = DateTime.Now,
                }
            };            
        }

        [Fact]
        public void GetTodos_ReturnsOkResult()
        {            
            _mockService.Setup(t => t.GetAll()).Returns(todos);

            var result = _todoesController.GetTodos();
            
            Assert.IsType<OkObjectResult>(result.Result as OkObjectResult);

        }

        [Fact]
        public void GetTodos_ReturnsAllItems()
        {            
            _mockService.Setup(x => x.GetAll()).Returns(todos);

            var result = _todoesController.GetTodos().Result as OkObjectResult;
            var items = Assert.IsType<List<Todo>>(result.Value);
            
            Assert.Equal(5, items.Count);
        }

        [Theory]
        [InlineData(9)]
        public void GetTodo_ReturnsNotFound(int id)
        {            
            var todo = todos.Find(x => x.Id == id);
            _mockService.Setup(t => t.GetById(id)).Returns(todo);

            var result = _todoesController.GetTodo(id);

            Assert.IsType<NotFoundResult>(result.Result);
        }

        [Theory]
        [InlineData(1)]
        public void GetBTodo_ReturnsOkResult(int id)
        {
            var todo = todos.Find(x => x.Id == id);
            _mockService.Setup(t => t.GetById(id)).Returns(todo);

            var result = _todoesController.GetTodo(id);

            Assert.IsType<OkObjectResult>(result.Result as OkObjectResult);
        }

        [Theory]
        [InlineData(3)]
        public void GetTodo_ReturnsRightItem(int id)
        {
            var todo = todos.Find(x => x.Id == id);
            _mockService.Setup(t => t.GetById(id)).Returns(todo);

            var result = _todoesController.GetTodo(id).Result as OkObjectResult;

            Assert.IsType<Todo>(result.Value);
            Assert.Equal(id, (result.Value as Todo).Id);
        }

        [Fact]
        public void PostTodo_ReturnsCreatedResponse()
        {
            var todo = todos[2];

            var result = _todoesController.PostTodo(todo);

            Assert.IsType<CreatedAtActionResult>(result.Result);
        }

        [Fact]
        public void PostTodo_ReturnedResponseHasCreatedTodo()
        {
            var todo = todos[0];

            var result = _todoesController.PostTodo(todo).Result as CreatedAtActionResult;
            var item = result.Value as Todo;

            Assert.IsType<Todo>(item);
            Assert.Equal("CV1", item.Title);
        }

        [Theory]
        [InlineData(-1)]
        public void DeleteTodo_ReturnsNotFound(int id)
        {
            var todo = todos.Find(t => t.Id == id);
            _mockService.Setup(t => t.GetById(id)).Returns(todo);

            var result = _todoesController.DeleteTodo(id);

            Assert.IsType<NotFoundResult>(result);
        }

        [Theory]
        [InlineData(1)]       
        public void DeleteTodo_ReturnsNoContent(int id)
        {
            var todo = todos.Find(t => t.Id == id);
            _mockService.Setup(t => t.GetById(id)).Returns(todo);

            var result = _todoesController.DeleteTodo(id);

            Assert.IsType<NoContentResult>(result);
        }        
    }
}
