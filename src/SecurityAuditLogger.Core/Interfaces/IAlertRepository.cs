using SecurityAuditLogger.Core.DTOs;
using SecurityAuditLogger.Core.Entities;

namespace SecurityAuditLogger.Core.Interfaces;

public interface IAlertRepository
{
    Task<Alert> AddAsync(Alert alert, CancellationToken ct = default);
    Task<Alert?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<AlertPageDto> GetPagedAsync(int page, int pageSize, bool? acknowledgedOnly = null, CancellationToken ct = default);
    Task<Alert> AcknowledgeAsync(Guid id, string acknowledgedBy, CancellationToken ct = default);
    Task<long> CountActiveAsync(CancellationToken ct = default);
}
