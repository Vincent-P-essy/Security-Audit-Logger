using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecurityAuditLogger.Core.DTOs;
using SecurityAuditLogger.Core.Interfaces;

namespace SecurityAuditLogger.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class AlertsController : ControllerBase
{
    private readonly IAlertRepository _alertRepository;

    public AlertsController(IAlertRepository alertRepository)
    {
        _alertRepository = alertRepository;
    }

    /// <summary>List alerts with optional acknowledgement filter.</summary>
    [HttpGet]
    [ProducesResponseType(typeof(AlertPageDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAlerts(
        [FromQuery] bool? acknowledgedOnly,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        CancellationToken ct = default)
    {
        var result = await _alertRepository.GetPagedAsync(page, pageSize, acknowledgedOnly, ct);
        return Ok(result);
    }

    /// <summary>Acknowledge an alert.</summary>
    [HttpPatch("{id:guid}/acknowledge")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Acknowledge(Guid id, [FromBody] AcknowledgeAlertDto dto, CancellationToken ct)
    {
        try
        {
            await _alertRepository.AcknowledgeAsync(id, dto.AcknowledgedBy, ct);
            return NoContent();
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
    }
}
