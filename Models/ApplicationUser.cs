using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Proj.Models
{
    public class ApplicationUser : IdentityUser<Guid>
    {
        [Required]
        [MaxLength(100)]
        public string FullName { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        public override string? Email { get => base.Email; set => base.Email = value; }

        public string? ProfileImageUrl { get; set; }

        public bool IsActive { get; set; } = true;
    }
}
