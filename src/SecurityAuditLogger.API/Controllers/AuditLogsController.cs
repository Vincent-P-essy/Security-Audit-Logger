using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecurityAuditLogger.Core.DTOs;
using SecurityAuditLogger.Core.Enums;
using SecurityAuditLogger.Core.Services;

namespace SecurityAuditLogger.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class AuditLogsController : ControllerBase
{
    private readonly AuditEventService _auditEventService;

    public AuditLogsController(AuditEventService auditEventService)
    {
        _auditEventService = auditEventService;
    }

    /// <summary>Record a new audit event.</summary>
    [HttpPost]
    [ProducesResponseType(typeof(AuditEventDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CreateEvent([FromBody] CreateAuditEventDto dto, CancellationToken ct)
    {
        var result = await _auditEventService.RecordAsync(dto, ct);
        return CreatedAtAction(nameof(GetEvent), new { id = result.Id }, result);
    }

    /// <summary>Get a single audit event by ID.</summary>
    [HttpGet("{id:guid}")]
    [ProducesResponseType(typeof(AuditEventDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetEvent(Guid id, CancellationToken ct)
    {
        var result = await _auditEventService.GetByIdAsync(id, ct);
        return result is null ? NotFound() : Ok(result);
    }

    /// <summary>List audit events with optional filters and pagination.</summary>
    [HttpGet]
    [ProducesResponseType(typeof(AuditEventPageDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetEvents(
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] string? username,
        [FromQuery] string? ipAddress,
        [FromQuery] AuditEventType? eventType,
        [FromQuery] bool? anomaliesOnly,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        CancellationToken ct = default)
    {
        var filter = new AuditEventFilterDto(from, to, username, ipAddress, eventType, anomaliesOnly, page, pageSize);
        var result = await _auditEventService.GetEventsAsync(filter, ct);
        return Ok(result);
    }

    /// <summary>Get dashboard summary for the last 24 hours.</summary>
    [HttpGet("dashboard")]
    [ProducesResponseType(typeof(DashboardSummaryDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetDashboard(CancellationToken ct)
    {
        var result = await _auditEventService.GetDashboardAsync(ct);
        return Ok(result);
    }
}
