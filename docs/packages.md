# Packages

All versions are pinned centrally in `backend/Directory.Packages.props`. Restore uses nuget.org only (`backend/nuget.config`).
Add new packages only through the task that needs them, and add a line here when you do.

## Runtime

| Package | Version | Used by | Why |
|---|---|---|---|
| Microsoft.EntityFrameworkCore.SqlServer | 10.0.13 | Auth.DAL | EF Core provider for the SQL Server `CentralAuth` database; compile assets kept private to DAL so Services cannot use EF. |
| Microsoft.Extensions.DependencyInjection.Abstractions | 10.0.13 | Auth.DAL, Auth.Services | `IServiceCollection` for the `AddDataAccess` / `AddAuthServices` registration extensions. |
| Konscious.Security.Cryptography.Argon2 | 1.3.1 | Auth.Services | Argon2id password hashing (plan A9: m=64 MiB, t=3, p=1), managed code, MIT. Pulls Konscious.Security.Cryptography.Blake2 1.1.1 (same author, MIT). Output checked against the RFC 9106 Argon2id test vector in the unit tests. |
| Microsoft.Extensions.Configuration.Abstractions | 10.0.13 | Auth.Services | `IConfiguration` for `AddAuthServices` to read the connection string and options. |
| Microsoft.IdentityModel.JsonWebTokens | 8.23.0 | Auth.Services, Auth.Client | Access-token creation and validation (T07, approved): JsonWebTokenHandler with ES256/RS256, pinned algorithms, kid-based key resolution. Brings Microsoft.IdentityModel.Tokens/Logging/Abstractions 8.23.0. ShowPII stays off. |
| Serilog.AspNetCore | 10.0.0 | Auth.Api | Structured logging with the RedactionEnricher (T09, on the allowed list). Brings Serilog 4.3, Settings.Configuration, Sinks.Console/Debug/File, Formatting.Compact. |

## Design time

| Package | Version | Used by | Why |
|---|---|---|---|
| Microsoft.EntityFrameworkCore.Design | 10.0.13 | Auth.DAL (`PrivateAssets="all"`, no compile assets) | Required by `dotnet ef migrations add/script` (T05); Auth.DAL is both project and startup project via `AuthDbContextFactory`. Never flows to Services, Api or the published host. Tool: global `dotnet-ef` 10.0.10. |

## Transitive security pins

| Package | Version | Why |
|---|---|---|
| System.Security.Cryptography.Pkcs | 10.0.13 | Microsoft.Data.SqlClient 6.1.7 pulls 9.0.11, which has advisories GHSA-846f-f764-76mx (high) and GHSA-2fmv-rv2c-59x7 (moderate). Pinned through `CentralPackageTransitivePinningEnabled`; remove the pin once SqlClient ships a fixed dependency. |

## Transitive alignment pins

| Package | Version | Why |
|---|---|---|
| Microsoft.IdentityModel.Abstractions, .Logging, .Tokens, .Protocols, .Protocols.OpenIdConnect, System.IdentityModel.Tokens.Jwt | 8.23.0 | Microsoft.Data.SqlClient 6.1.7 pulls the 7.7.1 IdentityModel family while JsonWebTokens is 8.23.0. Microsoft requires all IdentityModel packages on one version, so the whole family is pinned to 8.23.0 through `CentralPackageTransitivePinningEnabled`. SqlClient itself was built against 7.x: Windows and SQL authentication are tested, but **retest before using Microsoft Entra ID or Key Vault authentication for SQL** (threat-model.md, R17). |

## Test

| Package | Version | Used by | Why |
|---|---|---|---|
| xunit | 2.9.3 | all test projects | Test framework. |
| xunit.runner.visualstudio | 3.1.4 | all test projects | Lets `dotnet test` and IDEs discover and run the xUnit tests. |
| Microsoft.NET.Test.Sdk | 18.11.0 | all test projects | Test host required by `dotnet test`. |
| coverlet.collector | 6.0.4 | all test projects | Code-coverage collection (`dotnet test --collect "XPlat Code Coverage"`). |
| NetArchTest.Rules | 1.3.2 | Auth.ArchitectureTests | IL-level checks that layers depend only on what the rules allow. |
| Microsoft.AspNetCore.Mvc.Testing | 10.0.13 | Auth.IntegrationTests | WebApplicationFactory for hosting Auth.Api in tests (T09 acceptance; on the T00 approved plan list). |

## Planned (added by later tasks, approved in the T00 plan)

FluentValidation (T12; not added: hand-written validators do the job without a new dependency),
NSubstitute (first unit tests), Testcontainers.MsSql (optional; local SQL Express is the default).

## Frontend (npm, `frontend/package.json`, T23)

Exact versions with a committed `package-lock.json`; `frontend/.npmrc` sets `ignore-scripts=true` and
`save-exact=true`. None of the packages below has an install script, and `npm audit` reported 0
vulnerabilities at install (2026-10-26). The four dev-only additions were approved by god on 2026-10-26.

| Package | Version | Kind | Why |
|---|---|---|---|
| vue | 3.5.44 | runtime | UI framework (`<script setup>`, Composition API). |
| vue-router | 5.4.0 | runtime | Client routing. |
| pinia | 4.1.0 | runtime | Store for the non-sensitive user profile only. |
| vite | 8.3.5 | dev | Dev server, `/api` proxy and production build. |
| vitest | 5.0.5 | dev | Unit and component tests. |
| @vitejs/plugin-vue | 6.0.10 | dev (approved) | Vite cannot compile `.vue` single-file components without it. |
| typescript | 6.0.3 | dev (approved) | Strict typing. Not 7.x: vue-tsc relies on the JavaScript compiler API that 7.x (the native port) drops. |
| vue-tsc | 3.3.13 | dev (approved) | Type-checks `.vue` files in `npm run build` (plain tsc cannot read them). |
| jsdom | 30.1.3 | dev (approved) | Vitest DOM environment for component, accessibility and storage tests. |
| @playwright/test | 1.64.1 | dev (approved by the human, 2026-10-27, T-PW) | Browser end-to-end and accessibility suite in `frontend/e2e` (`npm run e2e`), separate from `npm test` and `npm run build`. Brings playwright and playwright-core 1.64.1 (Apache-2.0, no install scripts). The Chromium binary is not a package: `npx playwright install chromium` downloads it once from Microsoft's CDN into `%LOCALAPPDATA%\ms-playwright` (or `~/.cache/ms-playwright`), outside the repository. Published 2026-10-14. |
| @axe-core/playwright | 4.14.0 | dev (approved, T-PW) | Runs axe-core (4.14.0, MPL-2.0, brought with it) inside those pages for WCAG 2.0/2.1/2.2 A and AA rules. Published 2026-10-15. |

T-PW: `npm audit` reported 0 vulnerabilities after adding the two packages above (2026-10-27); none has an install
script (`ignore-scripts=true` stays).

Not used: @vue/test-utils (tests mount with `createApp`), @types/node (the e2e suite declares the four Node
functions it uses in `e2e/node-shim.d.ts`), any UI, icon or validation library.
