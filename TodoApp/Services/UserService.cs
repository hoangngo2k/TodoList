using AutoMapper;
using BCrypt.Net;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Options;
using TodoApp.Authorization;
using TodoApp.Entities;
using TodoApp.Helpers;
using TodoApp.Models.Users;

namespace TodoApp.Services
{
    public interface IUserService
    {
        AuthenticateResponse Authenticate(AuthenticateRequest request, string ipAddress);
        AuthenticateResponse RefreshToken(string token, string ipAdress);
        void RevokeToken(string token, string ipAddress);
        void Delete(int id);
        IEnumerable<User> GetAll();
        User GetById(int id);
        void Register(RegisterRequest request);
        void Update(int id, UpdateRequest request);
    }

    public class UserService : IUserService
    {
        private readonly DataContext _context;
        private IJwtUtils _jwtUtils;
        private IMapper _mapper;
        private readonly AppSettings _settings;

        public UserService(IMapper mapper, IJwtUtils jwtUtils, DataContext context, IOptions<AppSettings> settings)
        {
            _mapper = mapper;
            _jwtUtils = jwtUtils;
            _context = context;
            _settings = settings.Value;
        }

        public AuthenticateResponse Authenticate(AuthenticateRequest request, string ipAddress)
        {
            var user = _context.Users.SingleOrDefault(x => x.Username == request.Username);

            if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.Password))
            {
                throw new AppException("Username or password is incorrect");
            }

            var jwtToken = _jwtUtils.GenerateJwtToken(user);
            var refreshToken = _jwtUtils.GenerateRefreshToken(ipAddress);
            user.RefreshTokens.Add(refreshToken);

            removeOldRefreshTokens(user);

            _context.Users.Update(user);
            _context.SaveChanges();

            return new AuthenticateResponse(user, jwtToken, refreshToken.Token);
        }

        public AuthenticateResponse RefreshToken(string token, string ipAdress)
        {
            var user = getUserByRefreshToken(token);
            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            if (refreshToken.IsRevoked)
            {
                revokeDescendantRefreshTokens(refreshToken, user, ipAdress, $"Attempted reuse of revoked ancestor token: {token}");
                _context.Update(user);
                _context.SaveChanges();
            }

            if (!refreshToken.IsActive)
            {
                throw new AppException("Invalid token");
            }

            var newRefreshToken = rotateRefreshToken(refreshToken, ipAdress);
            user.RefreshTokens.Add(newRefreshToken);

            removeOldRefreshTokens(user);

            _context.Update(user);
            _context.SaveChanges();

            var jwtToken = _jwtUtils.GenerateJwtToken(user);

            return new AuthenticateResponse(user, jwtToken, newRefreshToken.Token);
        }

        public void Register(RegisterRequest request)
        {
            if (_context.Users.Any(x => x.Username == request.UserName))
            {
                throw new AppException("Username '" + request.UserName + "' is already taken");
            }

            var user = _mapper.Map<User>(request);
            user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);
            user.Role = Role.User;

            _context.Users.Add(user);
            _context.SaveChanges();
        }

        public void RevokeToken(string token, string ipAddress)
        {
            var user = getUserByRefreshToken(token);
            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            if (!refreshToken.IsActive)
            {
                throw new AppException("Invalid token");
            }

            revokeRefreshToken(refreshToken, ipAddress, "Revoked without replacement");
            _context.Update(user);
            _context.SaveChanges();
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

        private RefreshToken rotateRefreshToken(RefreshToken refreshToken, string ipAddress)
        {
            var newRefreshToken = _jwtUtils.GenerateRefreshToken(ipAddress);
            revokeRefreshToken(refreshToken, ipAddress, "Replaced by new token", newRefreshToken.Token);
            return newRefreshToken;
        }

        private void revokeDescendantRefreshTokens(RefreshToken refreshToken, User user, string ipAdress, string v)
        {
            if (!string.IsNullOrEmpty(refreshToken.ReplacedByToken))
            {
                var childToken = user.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken.ReplacedByToken);
                if (childToken.IsActive)
                {
                    revokeRefreshToken(childToken, ipAdress, v);
                }
                else
                {
                    revokeDescendantRefreshTokens(childToken, user, ipAdress, v);
                }
            }
        }

        private User getUserByRefreshToken(string token)
        {
            var user = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));

            if(user == null)
            {
                throw new AppException("Invalid token");
            }

            return user;
        }        

        private void revokeRefreshToken(RefreshToken refreshToken, string ipAdress, string v, string replacedByToken = null)
        {
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAdress;
            refreshToken.ReasonRevoked = v;
            refreshToken.ReplacedByToken = replacedByToken;
        }        

        private void removeOldRefreshTokens(User user)
        {
            user.RefreshTokens.RemoveAll(x =>
                !x.IsActive &&
                x.Created.AddDays(_settings.RefreshTokenTTL) <= DateTime.UtcNow);
        }
    }
}
