using System.Security.Claims;
using SecurityAuditLogger.Core.DTOs;
using SecurityAuditLogger.Core.Enums;
using SecurityAuditLogger.Core.Services;

namespace SecurityAuditLogger.API.Middleware;

public class AuditLoggingMiddleware
{
    private readonly RequestDelegate _next;

    // Endpoints excluded from automatic audit logging to avoid noise
    private static readonly HashSet<string> ExcludedPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/health", "/metrics", "/swagger", "/favicon.ico"
    };

    public AuditLoggingMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, AuditEventService auditEventService)
    {
        var path = context.Request.Path.Value ?? string.Empty;

        if (ShouldSkip(path))
        {
            await _next(context);
            return;
        }

        await _next(context);

        var username = context.User.Identity?.IsAuthenticated == true
            ? context.User.FindFirstValue(ClaimTypes.Name) ?? "anonymous"
            : "anonymous";

        var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var eventType = DetermineEventType(path, context.Response.StatusCode);

        if (eventType is null)
            return;

        var dto = new CreateAuditEventDto(
            EventType: eventType.Value,
            Username: username,
            IpAddress: ipAddress,
            Endpoint: path,
            HttpMethod: context.Request.Method,
            StatusCode: context.Response.StatusCode,
            UserAgent: context.Request.Headers.UserAgent.ToString(),
            Details: null
        );

        await auditEventService.RecordAsync(dto);
    }

    private static bool ShouldSkip(string path)
        => ExcludedPaths.Any(excluded => path.StartsWith(excluded, StringComparison.OrdinalIgnoreCase));

    private static AuditEventType? DetermineEventType(string path, int statusCode)
    {
        if (path.Contains("/auth/login", StringComparison.OrdinalIgnoreCase))
            return statusCode is >= 200 and < 300 ? AuditEventType.LoginSuccess : AuditEventType.LoginFailure;

        if (path.Contains("/auth/logout", StringComparison.OrdinalIgnoreCase))
            return AuditEventType.Logout;

        if (statusCode == 401 || statusCode == 403)
            return AuditEventType.UnauthorizedAccess;

        return AuditEventType.ApiAccess;
    }
}
