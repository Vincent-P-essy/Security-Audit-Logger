using Microsoft.EntityFrameworkCore;
using SecurityAuditLogger.Core.DTOs;
using SecurityAuditLogger.Core.Entities;
using SecurityAuditLogger.Core.Interfaces;
using SecurityAuditLogger.Infrastructure.Data;

namespace SecurityAuditLogger.Infrastructure.Repositories;

public class AlertRepository : IAlertRepository
{
    private readonly AppDbContext _db;

    public AlertRepository(AppDbContext db)
    {
        _db = db;
    }

    public async Task<Alert> AddAsync(Alert alert, CancellationToken ct = default)
    {
        _db.Alerts.Add(alert);
        await _db.SaveChangesAsync(ct);
        return alert;
    }

    public async Task<Alert?> GetByIdAsync(Guid id, CancellationToken ct = default)
        => await _db.Alerts.FindAsync(new object[] { id }, ct);

    public async Task<AlertPageDto> GetPagedAsync(int page, int pageSize, bool? acknowledgedOnly = null, CancellationToken ct = default)
    {
        var query = _db.Alerts.AsQueryable();

        if (acknowledgedOnly.HasValue)
            query = query.Where(a => a.IsAcknowledged == acknowledgedOnly.Value);

        var total = await query.LongCountAsync(ct);

        var items = await query
            .OrderByDescending(a => a.TriggeredAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(a => new AlertDto(
                a.Id, a.Severity, a.Title, a.Description,
                a.AffectedUsername, a.AffectedIpAddress,
                a.TriggeredAt, a.IsAcknowledged,
                a.AcknowledgedAt, a.AcknowledgedBy,
                a.RelatedAuditEventId))
            .ToListAsync(ct);

        return new AlertPageDto(items, page, pageSize, total);
    }

    public async Task<Alert> AcknowledgeAsync(Guid id, string acknowledgedBy, CancellationToken ct = default)
    {
        var alert = await _db.Alerts.FindAsync(new object[] { id }, ct)
            ?? throw new KeyNotFoundException($"Alert {id} not found.");

        alert.IsAcknowledged = true;
        alert.AcknowledgedAt = DateTime.UtcNow;
        alert.AcknowledgedBy = acknowledgedBy;

        await _db.SaveChangesAsync(ct);
        return alert;
    }

    public Task<long> CountActiveAsync(CancellationToken ct = default)
        => _db.Alerts.LongCountAsync(a => !a.IsAcknowledged, ct);
}
