using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Proj.Data;
using Proj.DTOs;
using Proj.Models;
using Proj.Repositories;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Proj.Services
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _userRepository;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _config;

        public UserService(IUserRepository userRepository, UserManager<ApplicationUser> userManager, IConfiguration config)
        {
            _userRepository = userRepository;
            _userManager = userManager;
            _config = config;
        }

        public async Task<(bool Succeeded, IEnumerable<string> Errors)> RegisterAsync(RegisterDto dto)
        {
            var errors = new List<string>();
            // Defensive: treat null as empty for all fields
            var email = dto.Email ?? string.Empty;
            var password = dto.Password ?? string.Empty;
            var confirmPassword = dto.ConfirmPassword ?? string.Empty;
            var fullName = dto.FullName ?? string.Empty;
            if (string.IsNullOrWhiteSpace(email)) errors.Add("Email is required.");
            if (string.IsNullOrWhiteSpace(password)) errors.Add("Password is required.");
            if (errors.Count > 0) return (false, errors);
            if (password != confirmPassword)
                return (false, new[] { "Passwords do not match." });
            var existingUser = await _userRepository.GetByEmailAsync(email);
            if (existingUser != null)
                return (false, new[] { "Email already registered." });
            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                FullName = fullName,
                Email = email,
                UserName = email
            };
            var result = await _userManager.CreateAsync(user, password);
            return (result.Succeeded, result.Errors.Select(e => e.Description));
        }

        public async Task<(bool Succeeded, string? Token, string? Error)> LoginAsync(LoginDto dto)
        {
            if (string.IsNullOrWhiteSpace(dto.Email))
                return (false, null, "Email is required.");
            if (string.IsNullOrWhiteSpace(dto.Password))
                return (false, null, "Password is required.");
            var user = await _userRepository.GetByEmailAsync(dto.Email);
            if (user == null)
                return (false, null, "Invalid credentials.");
            var passwordValid = await _userManager.CheckPasswordAsync(user, dto.Password);
            if (!passwordValid)
                return (false, null, "Invalid credentials.");

            var jwtSettings = _config.GetSection("Jwt");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email!),
                new Claim("FullName", user.FullName)
            };
            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(int.Parse(jwtSettings["ExpiresInMinutes"]!)),
                signingCredentials: creds
            );
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            return (true, tokenString, null);
        }

        public async Task<UserProfileDto?> GetProfileAsync(ClaimsPrincipal userPrincipal)
        {
            var userId = userPrincipal.FindFirstValue(ClaimTypes.NameIdentifier) ?? userPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);
            if (userId == null) return null;
            var user = await _userRepository.GetByIdAsync(Guid.Parse(userId));
            if (user == null) return null;
            return new UserProfileDto
            {
                FullName = user.FullName,
                Email = user.Email!,
                ProfileImageUrl = user.ProfileImageUrl
            };
        }

        public async Task<(bool Succeeded, IEnumerable<string> Errors)> UpdateProfileAsync(UpdateProfileDto dto, ClaimsPrincipal userPrincipal)
        {
            var userId = userPrincipal.FindFirstValue(ClaimTypes.NameIdentifier) ?? userPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);
            if (userId == null) return (false, new[] { "Unauthorized." });
            var user = await _userRepository.GetByIdAsync(Guid.Parse(userId));
            if (user == null) return (false, new[] { "User not found." });
            user.FullName = dto.FullName;
            user.Email = dto.Email;
            user.UserName = dto.Email;
            user.ProfileImageUrl = dto.ProfileImageUrl;
            await _userRepository.UpdateAsync(user);
            await _userRepository.SaveChangesAsync();
            return (true, Array.Empty<string>());
        }

        public async Task<(bool Succeeded, IEnumerable<string> Errors)> ChangePasswordAsync(ChangePasswordDto dto, ClaimsPrincipal userPrincipal)
        {
            var userId = userPrincipal.FindFirstValue(ClaimTypes.NameIdentifier) ?? userPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);
            if (userId == null) return (false, new[] { "Unauthorized." });
            var user = await _userRepository.GetByIdAsync(Guid.Parse(userId));
            if (user == null) return (false, new[] { "User not found." });
            if (dto.NewPassword != dto.ConfirmPassword)
                return (false, new[] { "Passwords do not match." });
            var result = await _userManager.ChangePasswordAsync(user, dto.OldPassword, dto.NewPassword);
            return (result.Succeeded, result.Errors.Select(e => e.Description));
        }

        public async Task<(bool Succeeded, IEnumerable<string> Errors)> DeactivateAccountAsync(ClaimsPrincipal userPrincipal)
        {
            var userId = userPrincipal.FindFirstValue(ClaimTypes.NameIdentifier) ?? userPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);
            if (userId == null) return (false, new[] { "Unauthorized." });
            var user = await _userRepository.GetByIdAsync(Guid.Parse(userId));
            if (user == null) return (false, new[] { "User not found." });
            user.IsActive = false;
            await _userRepository.UpdateAsync(user);
            await _userRepository.SaveChangesAsync();
            return (true, Array.Empty<string>());
        }

        public async Task<(bool Succeeded, string? Token, string? Error)> RefreshTokenAsync(RefreshTokenDto dto)
        {
            // For demo/interview: Accept a refresh token and return a new JWT (no real refresh token storage/validation here)
            // In production, implement secure refresh token storage and validation
            return (false, null, "Refresh token logic not implemented.");
        }

        public async Task<(bool Succeeded, IEnumerable<string> Errors)> ForgotPasswordAsync(ForgotPasswordDto dto)
        {
            var user = await _userRepository.GetByEmailAsync(dto.Email);
            if (user == null) return (false, new[] { "User not found." });
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            // In a real app, send token via email. For demo, just return success.
            return (true, new[] { token });
        }

        public async Task<(bool Succeeded, IEnumerable<string> Errors)> ResetPasswordAsync(ResetPasswordDto dto)
        {
            var user = await _userRepository.GetByEmailAsync(dto.Email);
            if (user == null) return (false, new[] { "User not found." });
            if (dto.NewPassword != dto.ConfirmPassword)
                return (false, new[] { "Passwords do not match." });
            var result = await _userManager.ResetPasswordAsync(user, dto.Token, dto.NewPassword);
            return (result.Succeeded, result.Errors.Select(e => e.Description));
        }
    }
}
