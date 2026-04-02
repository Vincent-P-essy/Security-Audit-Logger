using SecurityAuditLogger.Core.Entities;
using SecurityAuditLogger.Core.Enums;
using SecurityAuditLogger.Core.Interfaces;

namespace SecurityAuditLogger.Core.Services;

public class AnomalyDetectorService : IAnomalyDetector
{
    private readonly IAuditEventRepository _repository;

    // Business hours: 07:00–20:00 UTC
    private static readonly TimeSpan BusinessStart = TimeSpan.FromHours(7);
    private static readonly TimeSpan BusinessEnd = TimeSpan.FromHours(20);

    private const int BruteForceIpThreshold = 5;
    private const int BruteForceUserThreshold = 3;
    private static readonly TimeSpan BruteForceWindow = TimeSpan.FromMinutes(10);

    public AnomalyDetectorService(IAuditEventRepository repository)
    {
        _repository = repository;
    }

    public async Task<(bool IsAnomaly, string? Reason)> AnalyzeAsync(AuditEvent auditEvent, CancellationToken ct = default)
    {
        if (auditEvent.EventType == AuditEventType.LoginFailure)
        {
            var ipFailures = await _repository.CountLoginFailuresByIpAsync(auditEvent.IpAddress, BruteForceWindow, ct);
            if (ipFailures >= BruteForceIpThreshold)
                return (true, $"Brute force detected: {ipFailures} failed logins from IP {auditEvent.IpAddress} in the last 10 minutes.");

            var userFailures = await _repository.CountLoginFailuresByUserAsync(auditEvent.Username, BruteForceWindow, ct);
            if (userFailures >= BruteForceUserThreshold)
                return (true, $"Credential stuffing detected: {userFailures} failed logins for user '{auditEvent.Username}' in the last 10 minutes.");
        }

        if (IsOutsideBusinessHours(auditEvent.Timestamp))
        {
            bool hasNormalOffHoursHistory = await _repository.HasOffHoursAccessAsync(auditEvent.Username, auditEvent.Timestamp, ct);
            if (!hasNormalOffHoursHistory && auditEvent.EventType != AuditEventType.LoginFailure)
                return (true, $"Off-hours access: user '{auditEvent.Username}' accessed the system at {auditEvent.Timestamp:HH:mm} UTC (outside 07:00–20:00).");
        }

        return (false, null);
    }

    private static bool IsOutsideBusinessHours(DateTime timestampUtc)
    {
        var timeOfDay = timestampUtc.TimeOfDay;
        return timeOfDay < BusinessStart || timeOfDay > BusinessEnd;
    }
}
