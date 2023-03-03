using AutoMapper;
using BCrypt.Net;
using TodoApp.Authorization;
using TodoApp.Entities;
using TodoApp.Helpers;
using TodoApp.Models.Users;

namespace TodoApp.Services
{
    public interface IUserService
    {
        AuthenticateResponse Authenticate(AuthenticateRequest request);
        void Delete(int id);
        IEnumerable<User> GetAll();
        User GetById(int id);
        void Register(RegisterRequest request);
        void Update(int id, UpdateRequest request);
    }

    public class UserService : IUserService
    {
        private DataContext _context;
        private IJwtUtils _jwtUtils;
        private IMapper _mapper;

        public UserService(IMapper mapper, IJwtUtils jwtUtils, DataContext context)
        {
            _mapper = mapper;
            _jwtUtils = jwtUtils;
            _context = context;
        }

        public AuthenticateResponse Authenticate(AuthenticateRequest request)
        {
            var user = _context.Users.SingleOrDefault(x => x.Username == request.Username);

            if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.Password))
            {
                throw new AppException("Username or password is incorrect");
            }

            string token = _jwtUtils.GenerateJwtToken(user);
            return new AuthenticateResponse(user, token);
        }

        public void Delete(int id)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<User> GetAll()
        {
            return _context.Users;
        }

        public User GetById(int id)
        {
            return getUser(id);
        }

        public void Register(RegisterRequest request)
        {
            if(_context.Users.Any(x => x.Username == request.UserName))
            {
                throw new AppException("Username '" + request.UserName + "' is already taken");
            }

            var user = _mapper.Map<User>(request);
            user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);
            user.Role = Role.User;

            _context.Users.Add(user);
            _context.SaveChanges();
        }

        public void Update(int id, UpdateRequest request)
        {
            var user = getUser(id);

            if (request.UserName != user.Username && _context.Users.Any(x => x.Username == request.UserName))
                throw new AppException("Username '" + request.UserName + "' is already taken");
        }

        private User getUser(int id)
        {
            var user = _context.Users.Find(id);
            if (user == null) throw new KeyNotFoundException("User not found");
            return user;
        }
    }
}
