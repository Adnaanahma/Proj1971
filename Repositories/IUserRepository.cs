using Proj.Models;
using System;
using System.Threading.Tasks;

namespace Proj.Repositories
{
    public interface IUserRepository
    {
        Task<ApplicationUser?> GetByEmailAsync(string email);
        Task<ApplicationUser?> GetByIdAsync(Guid id);
        Task AddAsync(ApplicationUser user);
        Task UpdateAsync(ApplicationUser user);
        Task SaveChangesAsync();
    }
}
