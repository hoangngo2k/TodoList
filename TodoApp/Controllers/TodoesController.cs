using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TodoApp.Authorization;
using TodoApp.Entities;
using TodoApp.Helpers;
using TodoApp.Services;

namespace TodoApp.Controllers
{
    [Authorize(Role.Admin, Role.User)]
    [Route("api/[controller]")]
    [ApiController]
    public class TodoesController : ControllerBase
    {
        private readonly ITodoService _service;

        public TodoesController(ITodoService service)
        {
            _service = service;
        }

        // GET: api/Todoes
        [HttpGet]
        public ActionResult<IEnumerable<Todo>> GetTodos()
        {
            var todos = _service.GetAll();
            if (todos == null)
                return NotFound();
            return Ok(todos.ToList());
        }

        // GET: api/Todoes/5
        [HttpGet("{id}")]
        public ActionResult<Todo> GetTodo(int id)
        {
            var todo = _service.GetById(id);

            if (todo == null)
            {
                return NotFound();
            }

            return Ok(todo);
        }

        // PUT: api/Todoes/5
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPut("{id}")]
        public IActionResult PutTodo(int id, Todo todo)
        {
            if (id != todo.Id)
            {
                return BadRequest();
            }
            try
            {
                _service.Update(id, todo);
            }            
            catch (DbUpdateConcurrencyException)
            {
                if (!TodoExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }

        // POST: api/Todoes
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        public ActionResult<Todo> PostTodo(Todo todo)
        {            
            _service.Create(todo);

            return CreatedAtAction("GetTodo", new { id = todo.Id }, todo);
        }

        // DELETE: api/Todoes/5
        [HttpDelete("{id}")]
        public IActionResult DeleteTodo(int id)
        {
            var todo = _service.GetById(id);
            if (todo == null)
            {
                return NotFound();
            }

            _service.Delete(id);

            return NoContent();
        }

        //GET: api/Todos/filter?datefrom=2023-04-22 10:00:00&dateto=2023-04-28 23:00:00
        [HttpGet("filter")]
        public ActionResult<IEnumerable<Todo>> FilterDate([FromQuery(Name = "datefrom")] DateTime datefrom, 
            [FromQuery(Name = "dateto")] DateTime dateto)
        {                       
            return _service.FilterDateFromTo(datefrom, dateto).ToList();
        }

        private bool TodoExists(int id)
        {
            return _service.Exists(id);
        }
    }
}
