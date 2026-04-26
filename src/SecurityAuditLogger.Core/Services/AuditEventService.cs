using SecurityAuditLogger.Core.DTOs;
using SecurityAuditLogger.Core.Entities;
using SecurityAuditLogger.Core.Enums;
using SecurityAuditLogger.Core.Interfaces;

namespace SecurityAuditLogger.Core.Services;

public class AuditEventService
{
    private readonly IAuditEventRepository _eventRepository;
    private readonly IAlertRepository _alertRepository;
    private readonly IAnomalyDetector _anomalyDetector;

    public AuditEventService(
        IAuditEventRepository eventRepository,
        IAlertRepository alertRepository,
        IAnomalyDetector anomalyDetector)
    {
        _eventRepository = eventRepository;
        _alertRepository = alertRepository;
        _anomalyDetector = anomalyDetector;
    }

    public async Task<AuditEventDto> RecordAsync(CreateAuditEventDto dto, CancellationToken ct = default)
    {
        var auditEvent = new AuditEvent
        {
            EventType = dto.EventType,
            Username = dto.Username,
            IpAddress = dto.IpAddress,
            Endpoint = dto.Endpoint,
            HttpMethod = dto.HttpMethod,
            StatusCode = dto.StatusCode,
            UserAgent = dto.UserAgent,
            Details = dto.Details,
            Timestamp = DateTime.UtcNow
        };

        var (isAnomaly, reason) = await _anomalyDetector.AnalyzeAsync(auditEvent, ct);
        auditEvent.IsAnomaly = isAnomaly;
        auditEvent.AnomalyReason = reason;

        await _eventRepository.AddAsync(auditEvent, ct);

        if (isAnomaly)
            await RaiseAlertAsync(auditEvent, reason!, ct);

        return MapToDto(auditEvent);
    }

    public async Task<AuditEventDto?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        var e = await _eventRepository.GetByIdAsync(id, ct);
        return e is null ? null : MapToDto(e);
    }

    public Task<AuditEventPageDto> GetEventsAsync(AuditEventFilterDto filter, CancellationToken ct = default)
        => _eventRepository.GetPagedAsync(filter, ct);

    public Task<DashboardSummaryDto> GetDashboardAsync(CancellationToken ct = default)
        => _eventRepository.GetDashboardSummaryAsync(ct);

    private async Task RaiseAlertAsync(AuditEvent auditEvent, string reason, CancellationToken ct)
    {
        var severity = auditEvent.EventType == AuditEventType.LoginFailure
            ? AlertSeverity.High
            : AlertSeverity.Medium;

        var alert = new Alert
        {
            Severity = severity,
            Title = $"Anomaly Detected: {auditEvent.EventType}",
            Description = reason,
            AffectedUsername = auditEvent.Username,
            AffectedIpAddress = auditEvent.IpAddress,
            RelatedAuditEventId = auditEvent.Id
        };

        await _alertRepository.AddAsync(alert, ct);
    }

    public static AuditEventDto MapToDto(AuditEvent e) => new(
        e.Id, e.EventType, e.Username, e.IpAddress,
        e.Endpoint, e.HttpMethod, e.StatusCode, e.Timestamp,
        e.UserAgent, e.Details, e.IsAnomaly, e.AnomalyReason
    );
}
