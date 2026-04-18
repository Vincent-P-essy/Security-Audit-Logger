# Security Audit Logger

Outil de traçabilité et de détection d'anomalies pour APIs REST, développé en **C# / .NET 8** dans le cadre d'un projet de cybersécurité.

## Fonctionnalités

| Feature | Description |
|---|---|
| **Collecte de logs** | Enregistrement automatique de chaque requête HTTP via un middleware |
| **Détection d'anomalies** | Brute-force IP, credential stuffing, accès hors horaires (07h–20h UTC) |
| **Alertes automatiques** | Création d'alertes (Low/Medium/High/Critical) dès qu'une anomalie est détectée |
| **API REST + Swagger** | Dashboard, pagination, filtres par utilisateur/IP/type d'événement |
| **Authentification JWT** | Accès sécurisé avec rôles `Admin` et `Analyst` |
| **Base de données** | SQL Server (swappable Oracle via `Oracle.EntityFrameworkCore`) |
| **TDD** | Tests unitaires xUnit + Moq + FluentAssertions, tests d'intégration ASP.NET |
| **CI/CD** | GitHub Actions : build, tests, scan de vulnérabilités Trivy |
| **Docker** | Image multi-stage sécurisée (non-root), docker-compose avec SQL Server |

## Architecture

```
SecurityAuditLogger/
├── src/
│   ├── SecurityAuditLogger.Core/           # Domaine : entités, interfaces, services
│   │   ├── Entities/                       # AuditEvent, User, Alert
│   │   ├── Interfaces/                     # Contrats des repositories et services
│   │   ├── Services/                       # AnomalyDetectorService, AuditEventService, AuthService
│   │   └── DTOs/                           # Records d'entrée/sortie
│   ├── SecurityAuditLogger.Infrastructure/ # EF Core, repositories, JWT, BCrypt
│   └── SecurityAuditLogger.API/            # Controllers, middlewares, Program.cs
└── tests/
    ├── SecurityAuditLogger.UnitTests/       # Tests unitaires (TDD)
    └── SecurityAuditLogger.IntegrationTests/
```

L'architecture suit les principes **Clean Architecture** : le Core ne dépend d'aucune infrastructure.

## Détection d'anomalies

Trois règles implémentées dans `AnomalyDetectorService` :

1. **Brute force par IP** — ≥ 5 échecs de connexion en 10 minutes depuis la même IP → alerte `High`
2. **Credential stuffing** — ≥ 3 échecs pour le même utilisateur en 10 minutes → alerte `High`
3. **Accès hors horaires** — accès entre 20h et 7h UTC pour un utilisateur sans historique off-hours → alerte `Medium`

## Démarrage rapide

### Avec Docker Compose

```bash
docker compose up -d
```

L'API est accessible sur `http://localhost:8080/swagger`.

### En local

**Prérequis** : .NET 8 SDK, SQL Server (ou Docker)

```bash
# Configurer la base
cd src/SecurityAuditLogger.API
dotnet user-secrets set "Jwt:Secret" "votre-clé-secrète-de-32-caractères-min"

# Lancer l'API (migre automatiquement la DB en Development)
dotnet run
```

### Tests

```bash
# Tous les tests unitaires
dotnet test tests/SecurityAuditLogger.UnitTests/

# Tests d'intégration (in-memory DB)
dotnet test tests/SecurityAuditLogger.IntegrationTests/

# Couverture de code
dotnet test --collect:"XPlat Code Coverage"
```

## Endpoints principaux

| Méthode | Route | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/login` | Non | Obtenir un JWT |
| `POST` | `/api/auth/register` | Admin | Créer un utilisateur |
| `POST` | `/api/auditlogs` | Oui | Enregistrer un événement |
| `GET` | `/api/auditlogs` | Oui | Lister avec filtres et pagination |
| `GET` | `/api/auditlogs/dashboard` | Oui | Résumé 24h (top IPs, top users, anomalies) |
| `GET` | `/api/alerts` | Oui | Lister les alertes |
| `PATCH` | `/api/alerts/{id}/acknowledge` | Oui | Acquitter une alerte |
| `GET` | `/health` | Non | Health check |

## Stack technique

- **Langage** : C# 12 / .NET 8
- **Framework** : ASP.NET Core Web API
- **ORM** : Entity Framework Core 8 (SQL Server / Oracle)
- **Auth** : JWT Bearer (HS256), BCrypt pour les mots de passe
- **Tests** : xUnit, Moq, FluentAssertions, Microsoft.AspNetCore.Mvc.Testing
- **Logs** : Serilog (console + fichier rotatif)
- **CI** : GitHub Actions
- **Conteneurisation** : Docker (image non-root), Docker Compose

## Passage à Oracle

Remplacer dans `SecurityAuditLogger.Infrastructure.csproj` :
```xml
<PackageReference Include="Oracle.EntityFrameworkCore" Version="8.21.121" />
```
Et dans `Program.cs` :
```csharp
options.UseOracle(connectionString)
```

## Licence

MIT
