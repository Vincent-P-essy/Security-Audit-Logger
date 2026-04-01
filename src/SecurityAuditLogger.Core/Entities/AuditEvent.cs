using SecurityAuditLogger.Core.Enums;

namespace SecurityAuditLogger.Core.Entities;

public class AuditEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public AuditEventType EventType { get; set; }
    public string Username { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string Endpoint { get; set; } = string.Empty;
    public string HttpMethod { get; set; } = string.Empty;
    public int? StatusCode { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string? UserAgent { get; set; }
    public string? Details { get; set; }
    public bool IsAnomaly { get; set; } = false;
    public string? AnomalyReason { get; set; }
}
