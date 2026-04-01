using SecurityAuditLogger.Core.Enums;

namespace SecurityAuditLogger.Core.Entities;

public class Alert
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public AlertSeverity Severity { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string AffectedUsername { get; set; } = string.Empty;
    public string AffectedIpAddress { get; set; } = string.Empty;
    public DateTime TriggeredAt { get; set; } = DateTime.UtcNow;
    public bool IsAcknowledged { get; set; } = false;
    public DateTime? AcknowledgedAt { get; set; }
    public string? AcknowledgedBy { get; set; }
    public Guid? RelatedAuditEventId { get; set; }
}
