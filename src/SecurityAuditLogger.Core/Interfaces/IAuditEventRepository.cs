using SecurityAuditLogger.Core.DTOs;
using SecurityAuditLogger.Core.Entities;

namespace SecurityAuditLogger.Core.Interfaces;

public interface IAuditEventRepository
{
    Task<AuditEvent> AddAsync(AuditEvent auditEvent, CancellationToken ct = default);
    Task<AuditEvent?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<AuditEventPageDto> GetPagedAsync(AuditEventFilterDto filter, CancellationToken ct = default);
    Task<int> CountLoginFailuresByIpAsync(string ipAddress, TimeSpan window, CancellationToken ct = default);
    Task<int> CountLoginFailuresByUserAsync(string username, TimeSpan window, CancellationToken ct = default);
    Task<bool> HasOffHoursAccessAsync(string username, DateTime timestamp, CancellationToken ct = default);
    Task<DashboardSummaryDto> GetDashboardSummaryAsync(CancellationToken ct = default);
}
