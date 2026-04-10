using FluentAssertions;
using Moq;
using SecurityAuditLogger.Core.Entities;
using SecurityAuditLogger.Core.Enums;
using SecurityAuditLogger.Core.Interfaces;
using SecurityAuditLogger.Core.Services;
using Xunit;

namespace SecurityAuditLogger.UnitTests.Services;

public class AnomalyDetectorServiceTests
{
    private readonly Mock<IAuditEventRepository> _repositoryMock = new();
    private readonly AnomalyDetectorService _sut;

    public AnomalyDetectorServiceTests()
    {
        _sut = new AnomalyDetectorService(_repositoryMock.Object);
    }

    [Fact]
    public async Task AnalyzeAsync_BruteForceByIp_ReturnsAnomaly_WhenThresholdExceeded()
    {
        // Arrange
        var auditEvent = BuildLoginFailure("192.168.1.1", "user1");
        _repositoryMock
            .Setup(r => r.CountLoginFailuresByIpAsync("192.168.1.1", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(6); // above threshold of 5
        _repositoryMock
            .Setup(r => r.CountLoginFailuresByUserAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        // Act
        var (isAnomaly, reason) = await _sut.AnalyzeAsync(auditEvent);

        // Assert
        isAnomaly.Should().BeTrue();
        reason.Should().Contain("Brute force");
        reason.Should().Contain("192.168.1.1");
    }

    [Fact]
    public async Task AnalyzeAsync_BruteForceByIp_ReturnsNoAnomaly_WhenBelowThreshold()
    {
        // Arrange
        var auditEvent = BuildLoginFailure("192.168.1.1", "user1");
        _repositoryMock
            .Setup(r => r.CountLoginFailuresByIpAsync("192.168.1.1", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(3); // below threshold
        _repositoryMock
            .Setup(r => r.CountLoginFailuresByUserAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(1);

        // Act
        var (isAnomaly, _) = await _sut.AnalyzeAsync(auditEvent);

        // Assert
        isAnomaly.Should().BeFalse();
    }

    [Fact]
    public async Task AnalyzeAsync_CredentialStuffing_ReturnsAnomaly_WhenUserThresholdExceeded()
    {
        // Arrange
        var auditEvent = BuildLoginFailure("10.0.0.1", "victim_user");
        _repositoryMock
            .Setup(r => r.CountLoginFailuresByIpAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(2); // IP is fine
        _repositoryMock
            .Setup(r => r.CountLoginFailuresByUserAsync("victim_user", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(4); // above user threshold of 3

        // Act
        var (isAnomaly, reason) = await _sut.AnalyzeAsync(auditEvent);

        // Assert
        isAnomaly.Should().BeTrue();
        reason.Should().Contain("Credential stuffing");
        reason.Should().Contain("victim_user");
    }

    [Theory]
    [InlineData(3)]  // 03:00 UTC — outside business hours
    [InlineData(22)] // 22:00 UTC — outside business hours
    public async Task AnalyzeAsync_OffHoursAccess_ReturnsAnomaly_ForNewOffHoursUser(int hour)
    {
        // Arrange
        var timestamp = new DateTime(2024, 1, 15, hour, 0, 0, DateTimeKind.Utc);
        var auditEvent = new AuditEvent
        {
            EventType = AuditEventType.ApiAccess,
            Username = "regular_user",
            IpAddress = "10.0.0.1",
            Endpoint = "/api/data",
            HttpMethod = "GET",
            Timestamp = timestamp
        };

        _repositoryMock
            .Setup(r => r.HasOffHoursAccessAsync("regular_user", timestamp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false); // no prior off-hours history

        // Act
        var (isAnomaly, reason) = await _sut.AnalyzeAsync(auditEvent);

        // Assert
        isAnomaly.Should().BeTrue();
        reason.Should().Contain("Off-hours access");
        reason.Should().Contain("regular_user");
    }

    [Theory]
    [InlineData(9)]  // 09:00 UTC — inside business hours
    [InlineData(14)] // 14:00 UTC — inside business hours
    [InlineData(19)] // 19:00 UTC — inside business hours
    public async Task AnalyzeAsync_DuringBusinessHours_ReturnsNoAnomaly(int hour)
    {
        // Arrange
        var timestamp = new DateTime(2024, 1, 15, hour, 0, 0, DateTimeKind.Utc);
        var auditEvent = new AuditEvent
        {
            EventType = AuditEventType.ApiAccess,
            Username = "user1",
            IpAddress = "10.0.0.1",
            Endpoint = "/api/data",
            HttpMethod = "GET",
            Timestamp = timestamp
        };

        // Act
        var (isAnomaly, _) = await _sut.AnalyzeAsync(auditEvent);

        // Assert
        isAnomaly.Should().BeFalse();
    }

    [Fact]
    public async Task AnalyzeAsync_OffHoursUser_ReturnsNoAnomaly_WhenHasOffHoursHistory()
    {
        // Arrange
        var timestamp = new DateTime(2024, 1, 15, 2, 0, 0, DateTimeKind.Utc);
        var auditEvent = new AuditEvent
        {
            EventType = AuditEventType.ApiAccess,
            Username = "nightshift_user",
            IpAddress = "10.0.0.1",
            Endpoint = "/api/data",
            HttpMethod = "GET",
            Timestamp = timestamp
        };

        _repositoryMock
            .Setup(r => r.HasOffHoursAccessAsync("nightshift_user", timestamp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true); // regular off-hours worker

        // Act
        var (isAnomaly, _) = await _sut.AnalyzeAsync(auditEvent);

        // Assert
        isAnomaly.Should().BeFalse();
    }

    private static AuditEvent BuildLoginFailure(string ipAddress, string username) => new()
    {
        EventType = AuditEventType.LoginFailure,
        Username = username,
        IpAddress = ipAddress,
        Endpoint = "/api/auth/login",
        HttpMethod = "POST",
        Timestamp = DateTime.UtcNow
    };
}
