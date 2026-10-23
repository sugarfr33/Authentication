# Packages

All versions are pinned centrally in `backend/Directory.Packages.props`. Restore uses nuget.org only (`backend/nuget.config`).
Add new packages only through the task that needs them, and add a line here when you do.

## Runtime

| Package | Version | Used by | Why |
|---|---|---|---|
| Microsoft.EntityFrameworkCore.SqlServer | 10.0.13 | Auth.DAL | EF Core provider for the SQL Server `CentralAuth` database; compile assets kept private to DAL so Services cannot use EF. |
| Microsoft.Extensions.DependencyInjection.Abstractions | 10.0.13 | Auth.DAL, Auth.Services | `IServiceCollection` for the `AddDataAccess` / `AddAuthServices` registration extensions. |
| Microsoft.Extensions.Configuration.Abstractions | 10.0.13 | Auth.Services | `IConfiguration` for `AddAuthServices` to read the connection string and options. |

## Transitive security pins

| Package | Version | Why |
|---|---|---|
| System.Security.Cryptography.Pkcs | 10.0.13 | Microsoft.Data.SqlClient 6.1.7 pulls 9.0.11, which has advisories GHSA-846f-f764-76mx (high) and GHSA-2fmv-rv2c-59x7 (moderate). Pinned through `CentralPackageTransitivePinningEnabled`; remove the pin once SqlClient ships a fixed dependency. |

## Test

| Package | Version | Used by | Why |
|---|---|---|---|
| xunit | 2.9.3 | all test projects | Test framework. |
| xunit.runner.visualstudio | 3.1.4 | all test projects | Lets `dotnet test` and IDEs discover and run the xUnit tests. |
| Microsoft.NET.Test.Sdk | 18.11.0 | all test projects | Test host required by `dotnet test`. |
| coverlet.collector | 6.0.4 | all test projects | Code-coverage collection (`dotnet test --collect "XPlat Code Coverage"`). |
| NetArchTest.Rules | 1.3.2 | Auth.ArchitectureTests | IL-level checks that layers depend only on what the rules allow. |

## Planned (added by later tasks, approved in the T00 plan)

FluentValidation (T12), Serilog.AspNetCore (T09), Konscious.Security.Cryptography.Argon2 (T06), Microsoft.EntityFrameworkCore.Design (T05),
NSubstitute (first unit tests), Microsoft.AspNetCore.Mvc.Testing (integration tests), Testcontainers.MsSql (optional; local SQL Express is the default).
