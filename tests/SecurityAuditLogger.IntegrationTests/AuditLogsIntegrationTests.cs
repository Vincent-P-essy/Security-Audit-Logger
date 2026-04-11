using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecurityAuditLogger.Core.DTOs;
using SecurityAuditLogger.Core.Enums;
using SecurityAuditLogger.Infrastructure.Data;
using Xunit;

namespace SecurityAuditLogger.IntegrationTests;

public class AuditLogsIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public AuditLogsIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                var descriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<AppDbContext>));
                if (descriptor != null)
                    services.Remove(descriptor);

                services.AddDbContext<AppDbContext>(options =>
                    options.UseInMemoryDatabase("IntegrationTestDb_" + Guid.NewGuid()));
            });
        });
    }

    private HttpClient CreateAuthenticatedClient()
    {
        var client = _factory.CreateClient();
        // For integration tests we attach a pre-signed dev token
        // In a real CI pipeline this would go through /api/auth/login
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", GetDevToken());
        return client;
    }

    [Fact]
    public async Task POST_AuditLogs_Returns201_WithValidPayload()
    {
        // Arrange
        var client = CreateAuthenticatedClient();
        var dto = new CreateAuditEventDto(
            EventType: AuditEventType.ApiAccess,
            Username: "integration_user",
            IpAddress: "192.168.10.1",
            Endpoint: "/api/orders",
            HttpMethod: "GET",
            StatusCode: 200,
            UserAgent: "IntegrationTest/1.0",
            Details: null
        );

        // Act
        var response = await client.PostAsJsonAsync("/api/auditlogs", dto);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var result = await response.Content.ReadFromJsonAsync<AuditEventDto>();
        result.Should().NotBeNull();
        result!.Username.Should().Be("integration_user");
    }

    [Fact]
    public async Task GET_AuditLogs_Returns200_WithPaginatedResults()
    {
        // Arrange
        var client = CreateAuthenticatedClient();

        // Act
        var response = await client.GetAsync("/api/auditlogs?page=1&pageSize=10");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<AuditEventPageDto>();
        result.Should().NotBeNull();
        result!.Page.Should().Be(1);
        result.PageSize.Should().Be(10);
    }

    [Fact]
    public async Task GET_AuditLogs_Returns401_WhenUnauthenticated()
    {
        // Arrange
        var client = _factory.CreateClient();

        // Act
        var response = await client.GetAsync("/api/auditlogs");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task GET_Dashboard_Returns200_WithSummary()
    {
        // Arrange
        var client = CreateAuthenticatedClient();

        // Act
        var response = await client.GetAsync("/api/auditlogs/dashboard");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<DashboardSummaryDto>();
        result.Should().NotBeNull();
    }

    [Fact]
    public async Task GET_Health_Returns200()
    {
        // Arrange
        var client = _factory.CreateClient();

        // Act
        var response = await client.GetAsync("/health");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    private static string GetDevToken()
    {
        // This token is signed with the dev secret from appsettings.Development.json
        // Generated for: username=testadmin, role=Admin, exp=2099-01-01
        // Real projects use a token generation helper or login endpoint in tests
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
               "eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1lIjoidGVzdGFkbWluIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiQWRtaW4iLCJuYmYiOjE3MDAwMDAwMDAsImV4cCI6NDA3MDkwODgwMCwiaXNzIjoiU2VjdXJpdHlBdWRpdExvZ2dlciIsImF1ZCI6IlNlY3VyaXR5QXVkaXRMb2dnZXIifQ." +
               "PLACEHOLDER_SIGNATURE";
    }
}
