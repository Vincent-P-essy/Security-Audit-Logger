namespace SecurityAuditLogger.Core.DTOs;

public record LoginRequestDto(string Username, string Password);

public record LoginResponseDto(
    string AccessToken,
    string TokenType,
    int ExpiresIn,
    string Username,
    string Role
);

public record RegisterRequestDto(string Username, string Password, string Role);
