namespace SecurityAuditLogger.Core.Enums;

public enum AuditEventType
{
    LoginSuccess,
    LoginFailure,
    Logout,
    ApiAccess,
    UnauthorizedAccess,
    PasswordChange,
    AccountLocked,
    TokenRefresh,
    DataExport,
    AdminAction
}
