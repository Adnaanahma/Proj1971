using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Proj.DTOs;
using Proj.Services;
using System.Security.Claims;

namespace Proj.Controllers
{
    /// <summary>
    /// Controller for authentication endpoints (register, login, password reset, etc).
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;
        /// <summary>
        /// Constructor for AuthController.
        /// </summary>
        public AuthController(IUserService userService)
        {
            _userService = userService;
        }

        /// <summary>
        /// Register a new user account.
        /// </summary>
        /// <param name="dto">Registration data.</param>
        /// <returns>Status message.</returns>
        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto dto)
        {
            var (succeeded, errors) = await _userService.RegisterAsync(dto);
            if (!succeeded) return BadRequest(new { errors });
            return Ok(new { message = "Registration successful." });
        }

        /// <summary>
        /// Authenticate a user and return a JWT token.
        /// </summary>
        /// <param name="dto">Login data.</param>
        /// <returns>JWT token.</returns>
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDto dto)
        {
            var (succeeded, token, error) = await _userService.LoginAsync(dto);
            if (!succeeded) return BadRequest(new { message = error });
            return Ok(new { token });
        }

        /// <summary>
        /// Request a new JWT access token using a refresh token.
        /// </summary>
        /// <param name="dto">Refresh token data.</param>
        /// <returns>New JWT token.</returns>
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken(RefreshTokenDto dto)
        {
            var (succeeded, token, error) = await _userService.RefreshTokenAsync(dto);
            if (!succeeded) return BadRequest(new { message = error });
            return Ok(new { token });
        }

        /// <summary>
        /// Request a password reset token for a user.
        /// </summary>
        /// <param name="dto">Forgot password data.</param>
        /// <returns>Status message and reset token (for demo).</returns>
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordDto dto)
        {
            var (succeeded, errors) = await _userService.ForgotPasswordAsync(dto);
            if (!succeeded) return BadRequest(new { errors });
            // For demo: return token in response (in real app, send via email)
            return Ok(new { message = "Password reset token generated.", token = errors.FirstOrDefault() });
        }

        /// <summary>
        /// Reset a user's password using a reset token.
        /// </summary>
        /// <param name="dto">Reset password data.</param>
        /// <returns>Status message.</returns>
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto dto)
        {
            var (succeeded, errors) = await _userService.ResetPasswordAsync(dto);
            if (!succeeded) return BadRequest(new { errors });
            return Ok(new { message = "Password reset successful." });
        }
    }
}
