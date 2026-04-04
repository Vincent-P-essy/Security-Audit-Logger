using Microsoft.EntityFrameworkCore;
using SecurityAuditLogger.Core.Entities;
using SecurityAuditLogger.Core.Interfaces;
using SecurityAuditLogger.Infrastructure.Data;

namespace SecurityAuditLogger.Infrastructure.Repositories;

public class UserRepository : IUserRepository
{
    private readonly AppDbContext _db;

    public UserRepository(AppDbContext db)
    {
        _db = db;
    }

    public async Task<User?> GetByUsernameAsync(string username, CancellationToken ct = default)
        => await _db.Users.FirstOrDefaultAsync(u => u.Username == username, ct);

    public async Task<User> AddAsync(User user, CancellationToken ct = default)
    {
        _db.Users.Add(user);
        await _db.SaveChangesAsync(ct);
        return user;
    }

    public async Task<User> UpdateAsync(User user, CancellationToken ct = default)
    {
        _db.Users.Update(user);
        await _db.SaveChangesAsync(ct);
        return user;
    }

    public async Task<bool> ExistsAsync(string username, CancellationToken ct = default)
        => await _db.Users.AnyAsync(u => u.Username == username, ct);
}
