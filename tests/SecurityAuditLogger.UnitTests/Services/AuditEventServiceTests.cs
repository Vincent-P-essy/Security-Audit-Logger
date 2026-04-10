using FluentAssertions;
using Moq;
using SecurityAuditLogger.Core.DTOs;
using SecurityAuditLogger.Core.Entities;
using SecurityAuditLogger.Core.Enums;
using SecurityAuditLogger.Core.Interfaces;
using SecurityAuditLogger.Core.Services;
using Xunit;

namespace SecurityAuditLogger.UnitTests.Services;

public class AuditEventServiceTests
{
    private readonly Mock<IAuditEventRepository> _eventRepoMock = new();
    private readonly Mock<IAlertRepository> _alertRepoMock = new();
    private readonly Mock<IAnomalyDetector> _anomalyDetectorMock = new();
    private readonly AuditEventService _sut;

    public AuditEventServiceTests()
    {
        _sut = new AuditEventService(
            _eventRepoMock.Object,
            _alertRepoMock.Object,
            _anomalyDetectorMock.Object);
    }

    [Fact]
    public async Task RecordAsync_NormalEvent_SavesEventWithoutAnomaly()
    {
        // Arrange
        var dto = BuildCreateDto(AuditEventType.ApiAccess);
        _anomalyDetectorMock
            .Setup(d => d.AnalyzeAsync(It.IsAny<AuditEvent>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((false, (string?)null));
        _eventRepoMock
            .Setup(r => r.AddAsync(It.IsAny<AuditEvent>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditEvent e, CancellationToken _) => e);

        // Act
        var result = await _sut.RecordAsync(dto);

        // Assert
        result.IsAnomaly.Should().BeFalse();
        result.AnomalyReason.Should().BeNull();
        _alertRepoMock.Verify(r => r.AddAsync(It.IsAny<Alert>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task RecordAsync_AnomalousEvent_SavesEventAndRaisesAlert()
    {
        // Arrange
        var dto = BuildCreateDto(AuditEventType.LoginFailure);
        const string anomalyReason = "Brute force detected: 6 failed logins from IP 1.2.3.4";

        _anomalyDetectorMock
            .Setup(d => d.AnalyzeAsync(It.IsAny<AuditEvent>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((true, anomalyReason));
        _eventRepoMock
            .Setup(r => r.AddAsync(It.IsAny<AuditEvent>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditEvent e, CancellationToken _) => e);
        _alertRepoMock
            .Setup(r => r.AddAsync(It.IsAny<Alert>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Alert a, CancellationToken _) => a);

        // Act
        var result = await _sut.RecordAsync(dto);

        // Assert
        result.IsAnomaly.Should().BeTrue();
        result.AnomalyReason.Should().Be(anomalyReason);
        _alertRepoMock.Verify(r => r.AddAsync(
            It.Is<Alert>(a => a.Description == anomalyReason && a.Severity == AlertSeverity.High),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RecordAsync_AnomalousNonLoginEvent_RaisesAlertWithMediumSeverity()
    {
        // Arrange
        var dto = BuildCreateDto(AuditEventType.ApiAccess);
        _anomalyDetectorMock
            .Setup(d => d.AnalyzeAsync(It.IsAny<AuditEvent>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((true, "Off-hours access detected"));
        _eventRepoMock
            .Setup(r => r.AddAsync(It.IsAny<AuditEvent>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditEvent e, CancellationToken _) => e);
        _alertRepoMock
            .Setup(r => r.AddAsync(It.IsAny<Alert>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Alert a, CancellationToken _) => a);

        // Act
        await _sut.RecordAsync(dto);

        // Assert
        _alertRepoMock.Verify(r => r.AddAsync(
            It.Is<Alert>(a => a.Severity == AlertSeverity.Medium),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    private static CreateAuditEventDto BuildCreateDto(AuditEventType type) => new(
        EventType: type,
        Username: "testuser",
        IpAddress: "1.2.3.4",
        Endpoint: "/api/test",
        HttpMethod: "GET",
        StatusCode: 200,
        UserAgent: "TestAgent/1.0",
        Details: null
    );
}
