using SecurityAuditLogger.Core.Enums;

namespace SecurityAuditLogger.Core.DTOs;

public record AuditEventDto(
    Guid Id,
    AuditEventType EventType,
    string Username,
    string IpAddress,
    string Endpoint,
    string HttpMethod,
    int? StatusCode,
    DateTime Timestamp,
    string? UserAgent,
    string? Details,
    bool IsAnomaly,
    string? AnomalyReason
);

public record CreateAuditEventDto(
    AuditEventType EventType,
    string Username,
    string IpAddress,
    string Endpoint,
    string HttpMethod,
    int? StatusCode,
    string? UserAgent,
    string? Details
);
