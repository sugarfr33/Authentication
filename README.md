# Central Auth

A central authentication and SSO service: an ASP.NET Core (.NET 10) API on SQL Server, plus a Vue 3 frontend.
Status: scaffold (T01). Features land task by task; see `docs/`.

## Layout

```
backend/   Auth.sln: src/ (Api, Services, DAL, Entities, Contracts) and tests/ (Unit, Integration, Architecture)
frontend/  Vue 3 app (T23)
docs/      assumptions, packages, and later architecture, threat model and integration guide
```

Dependency rules: Api → Services + Contracts · Services → DAL + Entities + Contracts (no EF) · DAL → Entities.
`Auth.ArchitectureTests` enforces them.

## Getting started

Prerequisites: .NET SDK 10.0.x, and SQL Server Express (`.\SQLEXPRESS`) with Windows Authentication.

```bash
cd backend
dotnet build Auth.sln
dotnet test Auth.sln

# Local connection string (Windows auth, no secret). Keep it out of committed files:
dotnet user-secrets set "ConnectionStrings:CentralAuth" "Server=.\SQLEXPRESS;Database=CentralAuth;Trusted_Connection=True;TrustServerCertificate=True;" --project src/Auth.Api
dotnet run --project src/Auth.Api
```

`backend/src/Auth.Api/appsettings.Example.json` lists every setting the API reads.
