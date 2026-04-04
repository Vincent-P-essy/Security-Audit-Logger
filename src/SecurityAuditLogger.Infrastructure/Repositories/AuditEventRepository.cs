using Microsoft.EntityFrameworkCore;
using SecurityAuditLogger.Core.DTOs;
using SecurityAuditLogger.Core.Entities;
using SecurityAuditLogger.Core.Enums;
using SecurityAuditLogger.Core.Interfaces;
using SecurityAuditLogger.Core.Services;
using SecurityAuditLogger.Infrastructure.Data;

namespace SecurityAuditLogger.Infrastructure.Repositories;

public class AuditEventRepository : IAuditEventRepository
{
    private readonly AppDbContext _db;

    public AuditEventRepository(AppDbContext db)
    {
        _db = db;
    }

    public async Task<AuditEvent> AddAsync(AuditEvent auditEvent, CancellationToken ct = default)
    {
        _db.AuditEvents.Add(auditEvent);
        await _db.SaveChangesAsync(ct);
        return auditEvent;
    }

    public async Task<AuditEvent?> GetByIdAsync(Guid id, CancellationToken ct = default)
        => await _db.AuditEvents.FindAsync(new object[] { id }, ct);

    public async Task<AuditEventPageDto> GetPagedAsync(AuditEventFilterDto filter, CancellationToken ct = default)
    {
        var query = _db.AuditEvents.AsQueryable();

        if (filter.From.HasValue)
            query = query.Where(e => e.Timestamp >= filter.From.Value);
        if (filter.To.HasValue)
            query = query.Where(e => e.Timestamp <= filter.To.Value);
        if (!string.IsNullOrWhiteSpace(filter.Username))
            query = query.Where(e => e.Username == filter.Username);
        if (!string.IsNullOrWhiteSpace(filter.IpAddress))
            query = query.Where(e => e.IpAddress == filter.IpAddress);
        if (filter.EventType.HasValue)
            query = query.Where(e => e.EventType == filter.EventType.Value);
        if (filter.AnomaliesOnly == true)
            query = query.Where(e => e.IsAnomaly);

        var total = await query.LongCountAsync(ct);

        var items = await query
            .OrderByDescending(e => e.Timestamp)
            .Skip((filter.Page - 1) * filter.PageSize)
            .Take(filter.PageSize)
            .Select(e => AuditEventService.MapToDto(e))
            .ToListAsync(ct);

        return new AuditEventPageDto(items, filter.Page, filter.PageSize, total);
    }

    public async Task<int> CountLoginFailuresByIpAsync(string ipAddress, TimeSpan window, CancellationToken ct = default)
    {
        var since = DateTime.UtcNow - window;
        return await _db.AuditEvents.CountAsync(
            e => e.IpAddress == ipAddress
              && e.EventType == AuditEventType.LoginFailure
              && e.Timestamp >= since,
            ct);
    }

    public async Task<int> CountLoginFailuresByUserAsync(string username, TimeSpan window, CancellationToken ct = default)
    {
        var since = DateTime.UtcNow - window;
        return await _db.AuditEvents.CountAsync(
            e => e.Username == username
              && e.EventType == AuditEventType.LoginFailure
              && e.Timestamp >= since,
            ct);
    }

    public async Task<bool> HasOffHoursAccessAsync(string username, DateTime timestamp, CancellationToken ct = default)
    {
        // A user is considered a regular off-hours worker if they have more than 3 off-hours events in the last 30 days
        var since = timestamp.AddDays(-30);
        var businessStart = TimeSpan.FromHours(7);
        var businessEnd = TimeSpan.FromHours(20);

        var count = await _db.AuditEvents.CountAsync(
            e => e.Username == username
              && e.Timestamp >= since
              && (e.Timestamp.TimeOfDay < businessStart || e.Timestamp.TimeOfDay > businessEnd),
            ct);

        return count > 3;
    }

    public async Task<DashboardSummaryDto> GetDashboardSummaryAsync(CancellationToken ct = default)
    {
        var since24h = DateTime.UtcNow.AddHours(-24);
        var since1h = DateTime.UtcNow.AddHours(-1);

        var totalEvents = await _db.AuditEvents.LongCountAsync(e => e.Timestamp >= since24h, ct);
        var totalAnomalies = await _db.AuditEvents.LongCountAsync(e => e.Timestamp >= since24h && e.IsAnomaly, ct);

        var topFailingIps = await _db.AuditEvents
            .Where(e => e.EventType == AuditEventType.LoginFailure && e.Timestamp >= since24h)
            .GroupBy(e => e.IpAddress)
            .Select(g => new TopOffenderDto(g.Key, g.LongCount()))
            .OrderByDescending(x => x.FailureCount)
            .Take(5)
            .ToListAsync(ct);

        var topFailingUsers = await _db.AuditEvents
            .Where(e => e.EventType == AuditEventType.LoginFailure && e.Timestamp >= since24h)
            .GroupBy(e => e.Username)
            .Select(g => new TopOffenderDto(g.Key, g.LongCount()))
            .OrderByDescending(x => x.FailureCount)
            .Take(5)
            .ToListAsync(ct);

        var eventsPerHour = await _db.AuditEvents
            .Where(e => e.Timestamp >= since24h)
            .GroupBy(e => new { e.Timestamp.Date, Hour = e.Timestamp.Hour })
            .Select(g => new HourlyEventCountDto(
                new DateTime(g.Key.Date.Year, g.Key.Date.Month, g.Key.Date.Day, g.Key.Hour, 0, 0, DateTimeKind.Utc),
                g.LongCount(),
                g.LongCount(x => x.IsAnomaly)
            ))
            .OrderBy(x => x.Hour)
            .ToListAsync(ct);

        return new DashboardSummaryDto(
            totalEvents,
            totalAnomalies,
            0,
            0,
            topFailingIps,
            topFailingUsers,
            eventsPerHour
        );
    }
}
