using SecurityAuditLogger.Core.Entities;

namespace SecurityAuditLogger.Core.Interfaces;

public interface IUserRepository
{
    Task<User?> GetByUsernameAsync(string username, CancellationToken ct = default);
    Task<User> AddAsync(User user, CancellationToken ct = default);
    Task<User> UpdateAsync(User user, CancellationToken ct = default);
    Task<bool> ExistsAsync(string username, CancellationToken ct = default);
}
