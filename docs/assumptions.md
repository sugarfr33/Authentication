# Assumptions

The T00 plan was approved with all defaults A1–A16, plus these decisions made afterwards:

- **Single tenant.** There are no tenant columns or tables. Multi-tenancy would be a separate design change.
- **Database:** SQL Server. Local dev and test use SQL Express `.\SQLEXPRESS` with Windows Authentication: database `CentralAuth` for dev, `CentralAuth_Test` for integration tests. Testcontainers is optional. Ask before targeting any other server.
- **Authorization codes (T19)** live in `IDistributedCache`, not a table, so the schema stays at 12 tables.
- **Api never references Auth.DAL.** `Auth.Services.AddAuthServices` calls `Auth.DAL.AddDataAccess`.
  - Auth.DAL/Auth.Entities still flow *transitively* to the Api host, so they appear in `deps.json` and the publish output.
  - `Auth.ArchitectureTests` blocks any Api code that uses them, checking csproj references, IL type dependencies and assembly references.
  - Why not `DisableTransitiveProjectReferences`: it was tried in T01 and dropped. It left `Auth.Entities.dll` out of the Api output and recorded DAL only as an incidental reference, which risks a runtime `FileNotFoundException`.
- **EF Core never reaches Services or Api at compile time.** DAL references it with `PrivateAssets="compile;contentfiles;analyzers;build"`, which T01 verified: `using Microsoft.EntityFrameworkCore` fails to compile in both.
