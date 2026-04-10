using FluentAssertions;
using Moq;
using SecurityAuditLogger.Core.DTOs;
using SecurityAuditLogger.Core.Entities;
using SecurityAuditLogger.Core.Interfaces;
using SecurityAuditLogger.Core.Services;
using Xunit;

namespace SecurityAuditLogger.UnitTests.Services;

public class AuthServiceTests
{
    private readonly Mock<IUserRepository> _userRepoMock = new();
    private readonly Mock<IJwtService> _jwtServiceMock = new();
    private readonly Mock<IPasswordHasher> _hasherMock = new();
    private readonly AuthService _sut;

    public AuthServiceTests()
    {
        _sut = new AuthService(_userRepoMock.Object, _jwtServiceMock.Object, _hasherMock.Object);
    }

    [Fact]
    public async Task LoginAsync_ValidCredentials_ReturnsToken()
    {
        // Arrange
        var user = BuildActiveUser();
        _userRepoMock.Setup(r => r.GetByUsernameAsync("alice", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _hasherMock.Setup(h => h.Verify("secret", user.PasswordHash)).Returns(true);
        _userRepoMock.Setup(r => r.UpdateAsync(It.IsAny<User>(), It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _jwtServiceMock.Setup(j => j.GenerateToken(user)).Returns("jwt-token-abc");

        // Act
        var result = await _sut.LoginAsync(new LoginRequestDto("alice", "secret"));

        // Assert
        result.AccessToken.Should().Be("jwt-token-abc");
        result.Username.Should().Be("alice");
        result.Role.Should().Be("Analyst");
    }

    [Fact]
    public async Task LoginAsync_WrongPassword_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        var user = BuildActiveUser();
        _userRepoMock.Setup(r => r.GetByUsernameAsync("alice", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), user.PasswordHash)).Returns(false);
        _userRepoMock.Setup(r => r.UpdateAsync(It.IsAny<User>(), It.IsAny<CancellationToken>())).ReturnsAsync(user);

        // Act & Assert
        await _sut.Invoking(s => s.LoginAsync(new LoginRequestDto("alice", "wrong")))
            .Should().ThrowAsync<UnauthorizedAccessException>();
    }

    [Fact]
    public async Task LoginAsync_UnknownUser_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        _userRepoMock.Setup(r => r.GetByUsernameAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((User?)null);

        // Act & Assert
        await _sut.Invoking(s => s.LoginAsync(new LoginRequestDto("unknown", "pass")))
            .Should().ThrowAsync<UnauthorizedAccessException>();
    }

    [Fact]
    public async Task LoginAsync_LockedAccount_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        var user = BuildActiveUser();
        user.LockedUntil = DateTime.UtcNow.AddMinutes(10);
        _userRepoMock.Setup(r => r.GetByUsernameAsync("alice", It.IsAny<CancellationToken>())).ReturnsAsync(user);

        // Act & Assert
        await _sut.Invoking(s => s.LoginAsync(new LoginRequestDto("alice", "secret")))
            .Should().ThrowAsync<UnauthorizedAccessException>()
            .WithMessage("*locked*");
    }

    [Fact]
    public async Task LoginAsync_FiveConsecutiveFailures_LocksAccount()
    {
        // Arrange
        var user = BuildActiveUser();
        user.FailedLoginCount = 4;
        _userRepoMock.Setup(r => r.GetByUsernameAsync("alice", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), user.PasswordHash)).Returns(false);

        User? updatedUser = null;
        _userRepoMock.Setup(r => r.UpdateAsync(It.IsAny<User>(), It.IsAny<CancellationToken>()))
            .Callback<User, CancellationToken>((u, _) => updatedUser = u)
            .ReturnsAsync(user);

        // Act
        await _sut.Invoking(s => s.LoginAsync(new LoginRequestDto("alice", "wrong")))
            .Should().ThrowAsync<UnauthorizedAccessException>();

        // Assert
        updatedUser!.LockedUntil.Should().NotBeNull();
        updatedUser.LockedUntil.Should().BeAfter(DateTime.UtcNow);
    }

    [Fact]
    public async Task RegisterAsync_NewUser_CreatesUser()
    {
        // Arrange
        _userRepoMock.Setup(r => r.ExistsAsync("bob", It.IsAny<CancellationToken>())).ReturnsAsync(false);
        _hasherMock.Setup(h => h.Hash("pass123")).Returns("hashed_pass");
        _userRepoMock.Setup(r => r.AddAsync(It.IsAny<User>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((User u, CancellationToken _) => u);

        // Act
        await _sut.RegisterAsync(new RegisterRequestDto("bob", "pass123", "Analyst"));

        // Assert
        _userRepoMock.Verify(r => r.AddAsync(
            It.Is<User>(u => u.Username == "bob" && u.PasswordHash == "hashed_pass"),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RegisterAsync_DuplicateUsername_ThrowsInvalidOperationException()
    {
        // Arrange
        _userRepoMock.Setup(r => r.ExistsAsync("alice", It.IsAny<CancellationToken>())).ReturnsAsync(true);

        // Act & Assert
        await _sut.Invoking(s => s.RegisterAsync(new RegisterRequestDto("alice", "pass", "Analyst")))
            .Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*already taken*");
    }

    private static User BuildActiveUser() => new()
    {
        Username = "alice",
        PasswordHash = "hashed_secret",
        Role = "Analyst",
        IsActive = true
    };
}
