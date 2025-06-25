using Proj.DTOs;
using Proj.Models;
using System.Security.Claims;

namespace Proj.Services
{
    public interface IUserService
    {
        Task<(bool Succeeded, IEnumerable<string> Errors)> RegisterAsync(RegisterDto dto);
        Task<(bool Succeeded, string? Token, string? Error)> LoginAsync(LoginDto dto);
        Task<UserProfileDto?> GetProfileAsync(ClaimsPrincipal userPrincipal);
        Task<(bool Succeeded, IEnumerable<string> Errors)> UpdateProfileAsync(UpdateProfileDto dto, ClaimsPrincipal userPrincipal);
        Task<(bool Succeeded, IEnumerable<string> Errors)> ChangePasswordAsync(ChangePasswordDto dto, ClaimsPrincipal userPrincipal);
        Task<(bool Succeeded, IEnumerable<string> Errors)> DeactivateAccountAsync(ClaimsPrincipal userPrincipal);
        Task<(bool Succeeded, string? Token, string? Error)> RefreshTokenAsync(RefreshTokenDto dto);
        Task<(bool Succeeded, IEnumerable<string> Errors)> ForgotPasswordAsync(ForgotPasswordDto dto);
        Task<(bool Succeeded, IEnumerable<string> Errors)> ResetPasswordAsync(ResetPasswordDto dto);
    }
}
