using SecurityAuditLogger.Core.Enums;

namespace SecurityAuditLogger.Core.DTOs;

public record DashboardSummaryDto(
    long TotalEventsLast24h,
    long TotalAnomaliesLast24h,
    long ActiveAlerts,
    long CriticalAlerts,
    IReadOnlyList<TopOffenderDto> TopFailingIps,
    IReadOnlyList<TopOffenderDto> TopFailingUsers,
    IReadOnlyList<HourlyEventCountDto> EventsPerHour
);

public record TopOffenderDto(string Identifier, long FailureCount);

public record HourlyEventCountDto(DateTime Hour, long Count, long AnomalyCount);

public record AuditEventPageDto(
    IReadOnlyList<AuditEventDto> Items,
    int Page,
    int PageSize,
    long TotalCount
);

public record AlertPageDto(
    IReadOnlyList<AlertDto> Items,
    int Page,
    int PageSize,
    long TotalCount
);

public record AuditEventFilterDto(
    DateTime? From,
    DateTime? To,
    string? Username,
    string? IpAddress,
    AuditEventType? EventType,
    bool? AnomaliesOnly,
    int Page = 1,
    int PageSize = 50
);
