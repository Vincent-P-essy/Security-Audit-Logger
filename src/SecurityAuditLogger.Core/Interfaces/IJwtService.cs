using SecurityAuditLogger.Core.Entities;

namespace SecurityAuditLogger.Core.Interfaces;

public interface IJwtService
{
    string GenerateToken(User user);
    bool ValidateToken(string token, out string? username, out string? role);
}
