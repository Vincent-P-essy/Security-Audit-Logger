using SecurityAuditLogger.Core.Entities;

namespace SecurityAuditLogger.Core.Interfaces;

public interface IAnomalyDetector
{
    Task<(bool IsAnomaly, string? Reason)> AnalyzeAsync(AuditEvent auditEvent, CancellationToken ct = default);
}
