using TodoApp.Services;

namespace TodoApp.Authorization
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _requestDelegate;

        public JwtMiddleware(RequestDelegate requestDelegate)
        {
            _requestDelegate = requestDelegate;
        }

        public async Task Invoke(HttpContext context, IUserService userService, IJwtUtils jwtUtils)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            var id = jwtUtils.ValidateToken(token);
            if (id != null)
            {
                context.Items["User"] = userService.GetById((int)id);
            }
            await _requestDelegate(context);
        }
    }
}
