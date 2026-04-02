using SecurityAuditLogger.Core.Enums;

namespace SecurityAuditLogger.Core.DTOs;

public record AlertDto(
    Guid Id,
    AlertSeverity Severity,
    string Title,
    string Description,
    string AffectedUsername,
    string AffectedIpAddress,
    DateTime TriggeredAt,
    bool IsAcknowledged,
    DateTime? AcknowledgedAt,
    string? AcknowledgedBy,
    Guid? RelatedAuditEventId
);

public record AcknowledgeAlertDto(string AcknowledgedBy);
