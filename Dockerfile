# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY SecurityAuditLogger.sln .
COPY src/SecurityAuditLogger.Core/SecurityAuditLogger.Core.csproj src/SecurityAuditLogger.Core/
COPY src/SecurityAuditLogger.Infrastructure/SecurityAuditLogger.Infrastructure.csproj src/SecurityAuditLogger.Infrastructure/
COPY src/SecurityAuditLogger.API/SecurityAuditLogger.API.csproj src/SecurityAuditLogger.API/

RUN dotnet restore

COPY src/ src/

RUN dotnet publish src/SecurityAuditLogger.API/SecurityAuditLogger.API.csproj \
    -c Release \
    -o /app/publish \
    --no-restore

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
USER appuser

COPY --from=build /app/publish .

ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["dotnet", "SecurityAuditLogger.API.dll"]
