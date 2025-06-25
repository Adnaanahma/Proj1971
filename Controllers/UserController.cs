using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Proj.DTOs;
using Proj.Services;
using System.Security.Claims;

namespace Proj.Controllers
{
    /// <summary>
    /// Controller for user profile and account management endpoints.
    /// All routes require authentication.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        /// <summary>
        /// Constructor for UserController.
        /// </summary>
        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        /// <summary>
        /// Get the current user's profile information.
        /// </summary>
        /// <returns>User profile data.</returns>
        [HttpGet("profile")]
        public async Task<IActionResult> GetProfile()
        {
            var profile = await _userService.GetProfileAsync(User);
            if (profile == null) return Unauthorized();
            return Ok(profile);
        }

        /// <summary>
        /// Update the current user's profile information.
        /// </summary>
        /// <param name="dto">Profile update data.</param>
        /// <returns>Status message.</returns>
        [HttpPut("profile")]
        public async Task<IActionResult> UpdateProfile(UpdateProfileDto dto)
        {
            var (succeeded, errors) = await _userService.UpdateProfileAsync(dto, User);
            if (!succeeded) return BadRequest(new { errors });
            return Ok(new { message = "Profile updated." });
        }

        /// <summary>
        /// Change the current user's password.
        /// </summary>
        /// <param name="dto">Password change data.</param>
        /// <returns>Status message.</returns>
        [HttpPut("change-password")]
        public async Task<IActionResult> ChangePassword(ChangePasswordDto dto)
        {
            var (succeeded, errors) = await _userService.ChangePasswordAsync(dto, User);
            if (!succeeded) return BadRequest(new { errors });
            return Ok(new { message = "Password changed successfully." });
        }

        /// <summary>
        /// Deactivate (soft delete) the current user's account.
        /// </summary>
        /// <returns>Status message.</returns>
        [HttpPost("deactivate")]
        public async Task<IActionResult> Deactivate()
        {
            var (succeeded, errors) = await _userService.DeactivateAccountAsync(User);
            if (!succeeded) return BadRequest(new { errors });
            return Ok(new { message = "Account deactivated." });
        }
    }
}
