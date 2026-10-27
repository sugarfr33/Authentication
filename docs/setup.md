# Local setup from a clean clone

These steps take a fresh clone to a running API and SPA with a signed-in administrator. They were followed word for
word in a fresh clone of `main` (94fd63c) on 2026-10-26 (T27). That run used a throwaway database and environment
variables instead of User Secrets; both are shown below.

Production settings (proxy, hosts, HSTS, CSP, keys) are in [deployment.md](deployment.md).

## 0. Prerequisites

The versions below are the ones **used** for this guide, not minimums, unless the notes say otherwise.

| Tool | Used | Required | Notes |
|---|---|---|---|
| .NET SDK | 10.0.403 | 10.0.x | `dotnet --version` must print 10.0.x. |
| dotnet-ef (global tool) | 10.0.10 | 10.0.x | `dotnet tool install --global dotnet-ef --version 10.0.10` |
| SQL Server Express | instance `.\SQLEXPRESS`, Windows Authentication | SQL Server 2019 or newer | Other instances work with a changed connection string. |
| sqlcmd | ODBC sqlcmd 17 | any | Or SQL Server Management Studio, to run one SQL file. |
| Node.js / npm | 24.22.1 / 12.2.1 | Node 20.19 or newer (`frontend/package.json` engines) | Only for the SPA, and to create the signing key (step 3). |

Commands below are for bash (Git Bash on Windows). PowerShell equivalents are given where they differ.

## 1. Clone, build and test

```bash
git clone <repo-url> Authentication
cd Authentication/backend
dotnet build Auth.sln          # expect 0 warnings, 0 errors
dotnet test Auth.sln           # unit and architecture tests run anywhere; integration tests need .\SQLEXPRESS
```

The integration tests create and drop their own `CentralAuth_*_Test` databases. They never touch `CentralAuth`. If
they time out on a busy machine, see [test-matrix.md](test-matrix.md), "Running the database suites reliably".

## 2. Create the database

The API does **not** migrate at startup. Create the schema once, and again after pulling new migrations.

```bash
# Still in backend/. Used only by dotnet ef (AuthDbContextFactory); the API reads ConnectionStrings:CentralAuth.
export CENTRALAUTH_CONNECTION='Server=.\SQLEXPRESS;Database=CentralAuth;Trusted_Connection=True;TrustServerCertificate=True;'
dotnet ef database update --project src/Auth.DAL --startup-project src/Auth.DAL
```

PowerShell: `$env:CENTRALAUTH_CONNECTION = 'Server=.\SQLEXPRESS;...'`.

- `--startup-project` must be **Auth.DAL**. With Auth.Api as the startup project the tool fails with "doesn't
  reference Microsoft.EntityFrameworkCore.Design". This is by design, so the design package never reaches the host.
- Without `CENTRALAUTH_CONNECTION` the tool uses the local default above (database `CentralAuth`).
- Expected: six migrations applied (`InitialCreate` up to `ApplicationRolesRequireRole`), and 14 tables in schema `auth`
  (13 plus `__EFMigrationsHistory`).
- Without the EF tool: `sqlcmd -S '.\SQLEXPRESS' -E -d CentralAuth -b -i ../docs/CentralAuth.initial.sql` applies the
  same migrations as an idempotent script. Create the empty database first (`CREATE DATABASE CentralAuth`).

## 3. Create the first signing key

Access tokens are signed with a key whose **public** JWK lives in `auth.SigningKey` and whose **private** PEM lives in
the secret store (configuration). The API's maintenance command `signing-key add` publishes a key through
`ISigningKeyRotation.AddKeyAsync`, then exits without starting the web host (T29).

1. Create the private key **outside the repository**, for example in `~/centralauth-keys/`. Node is enough:

   ```bash
   mkdir -p ~/centralauth-keys && cd ~/centralauth-keys
   node -e "const c=require('node:crypto');const {privateKey}=c.generateKeyPairSync('ec',{namedCurve:'P-256'});require('node:fs').writeFileSync('signingkey1.pem',privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600,flag:'wx'})"
   ```

   Or use OpenSSL: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out signingkey1.pem`.
2. Tell the API where the database and the key are (User Secrets, as in step 4):

   ```bash
   cd <repo>/backend
   dotnet user-secrets set "ConnectionStrings:CentralAuth" "Server=.\SQLEXPRESS;Database=CentralAuth;Trusted_Connection=True;TrustServerCertificate=True;" --project src/Auth.Api
   dotnet user-secrets set "SecretFiles:signingkey1" "$HOME/centralauth-keys/signingkey1.pem" --project src/Auth.Api
   ```

3. Publish the key:

   ```bash
   dotnet run --project src/Auth.Api -- signing-key add signingkey1 --reference signingkey1
   # Signing key 'signingkey1' (ES256) is published and signs from 2026-10-26T10:08:30Z (UTC).
   ```

The command:

- **Options:** `signing-key add <kid> --reference <secret name> [--algorithm ES256|RS256] [--activate-at <UTC time>]`.
  The default algorithm is ES256. Any other argument (such as `--environment Production`) configures the host as
  usual.
- **`--reference` is the secret's name, never the PEM itself.** The value is stored in `SigningKey.PrivateKeyReference`
  and stays in your shell history. The command refuses a value that looks like a PEM (usage error, exit 2).
- **Exit codes:** 0 when the key was added; 1 when it was not added (refused, or the database or secret store failed),
  with one line on stderr and no stack trace; 2 for a usage error, reported before the host is built.
- **Audit:** each added key writes a `SigningKeyAdded` row (kid, algorithm, activation time; no actor) in the same save
  as the key ([audit-and-retention.md](audit-and-retention.md)).
- **Checks:** it loads the PEM from the secret store and derives the public JWK from it, so the row always matches the
  key. It refuses a kid that already exists, a missing secret, or a PEM of the wrong type.
- **The first key** (nothing published yet) signs at once.
- **Every later key** must be published at least the token lifetime plus clock skew (15.5 minutes) before it signs,
  because resource servers cache the JWKS. Without `--activate-at` the command refuses, and names the earliest time
  allowed:

  ```bash
  dotnet run --project src/Auth.Api -- signing-key add signingkey2 --reference signingkey2 --activate-at 2026-10-27T08:00:00Z
  ```

  Then follow [single-logout-and-shared-domain.md](single-logout-and-shared-domain.md), section 3, and
  [t22-client-extension.md](t22-client-extension.md), "Key revocation runbook".
- **On a server**, run the published app the same way, with the environment's configuration:
  `dotnet Auth.Api.dll signing-key add <kid> --reference <kid>`.

At startup the API loads each key's PEM, checks it matches the stored public JWK, and refuses to sign with a key that
does not.

### Fallback without the command: SQL recipe

Use this only when the API cannot be run against the database, for the **first** key. Save this script **outside the
repository** as `make-signing-key.mjs`:

```js
// Creates the first ES256 signing key: a private PEM file (keep it out of the repo) and the SQL that publishes it.
// Usage: node make-signing-key.mjs <kid>   (kid: letters, digits and underscores only)
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const kid = process.argv[2] ?? 'signingkey1';
if (!/^[A-Za-z0-9_]{1,64}$/.test(kid)) throw new Error('kid must be 1-64 letters, digits or underscores');

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
writeFileSync(kid + '.pem', privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
const { x, y } = publicKey.export({ format: 'jwk' });
const jwk = JSON.stringify({ kty: 'EC', use: 'sig', kid, alg: 'ES256', crv: 'P-256', x, y });
writeFileSync(kid + '.sql',
  'INSERT INTO auth.SigningKey (Id, Kid, Algorithm, PublicKeyJwk, PrivateKeyReference, Status, CreatedUtc, ActivatedUtc)\n' +
  `VALUES ('${randomUUID()}', N'${kid}', N'ES256', N'${jwk}', N'${kid}', N'Active', SYSUTCDATETIME(), SYSUTCDATETIME());\n`,
  { flag: 'wx' });
console.log('Wrote ' + kid + '.pem (private, secret) and ' + kid + '.sql (public key row).');
```

```bash
cd ~/centralauth-keys
node make-signing-key.mjs signingkey1
sqlcmd -S '.\SQLEXPRESS' -E -d CentralAuth -b -i signingkey1.sql
```

- The script refuses to overwrite existing files, and the PEM never passes through the database or a log.
- Use this recipe **only for the first key**. It skips the overlap rule, so it must never add a second key.

### Naming rule for secrets

A secret named `n` is read from `Secrets:n` (the PEM text) or `SecretFiles:n` (a path to the PEM file). As an
environment variable that is `Secrets__n` or `SecretFiles__n`.

**Name signing keys with letters, digits and underscores only** (`signingkey1`, `signing_key_1`). The name you choose
becomes part of an environment variable name.

- **A hyphen breaks `export` in bash.** `export Secrets__signing-key-1=...` fails with "not a valid identifier", so
  the key is "not found". This happened in the T26 verification.
- A colon is refused outright (it is the configuration separator).
- **Names fixed by the code still contain a hyphen:** the MFA keys `MfaEncryptionKey-<id>` ([mfa-totp.md](mfa-totp.md)).
  Supply those through a source that allows the hyphen:
  - User Secrets or JSON: `dotnet user-secrets set "Secrets:MfaEncryptionKey-k1" "<base64>"`;
  - a file: `SecretFiles:MfaEncryptionKey-k1` = path;
  - bash without `export`: `env 'Secrets__MfaEncryptionKey-k1=<base64>' dotnet run ...`;
  - PowerShell `${env:Secrets__MfaEncryptionKey-k1} = '<base64>'`;
  - Docker `-e`, Kubernetes `env:` and systemd `Environment=`, which all accept the name as is.

## 4. Configure and run the API

Development settings go in User Secrets. They are stored per user under the id `central-auth-api`, outside the repo.

```bash
cd <repo>/backend   # back to the repo's backend folder
P=src/Auth.Api
dotnet user-secrets set "ConnectionStrings:CentralAuth" "Server=.\SQLEXPRESS;Database=CentralAuth;Trusted_Connection=True;TrustServerCertificate=True;" --project $P
dotnet user-secrets set "SecretFiles:signingkey1" "$HOME/centralauth-keys/signingkey1.pem" --project $P
# The SPA dev server (step 5). The Vite proxy keeps the browser's Origin, so the API must trust it.
dotnet user-secrets set "BrowserProtection:TrustedOrigins:0" "http://localhost:5173" --project $P
# Links in emails and the OAuth login page point at the SPA. The Vite dev server is plain http.
dotnet user-secrets set "AccountEmail:VerifyEmailUrl" "http://localhost:5173/verify-email" --project $P
dotnet user-secrets set "AccountEmail:ResetPasswordUrl" "http://localhost:5173/reset-password" --project $P
dotnet user-secrets set "OAuth:LoginUrl" "http://localhost:5173/login" --project $P
# Development emails are written as .eml files here (default: <temp>/centralauth-mail).
dotnet user-secrets set "DevelopmentEmail:PickupDirectory" "$HOME/centralauth-mail" --project $P

dotnet run --project $P --launch-profile https
```

On Windows, give `SecretFiles:signingkey1` an absolute Windows path (`C:/Users/<you>/centralauth-keys/signingkey1.pem`).

Environment variables work as well: replace `:` with `__`. This is what the clean-clone check used, so that the
machine's shared User Secrets stayed untouched:

```bash
export ASPNETCORE_ENVIRONMENT=Development
export ConnectionStrings__CentralAuth='Server=.\SQLEXPRESS;Database=CentralAuth;Trusted_Connection=True;TrustServerCertificate=True;'
export SecretFiles__signingkey1="$HOME/centralauth-keys/signingkey1.pem"
export BrowserProtection__TrustedOrigins__0='http://localhost:5173'
# ...and so on for the other settings above
```

Check it:

```bash
curl -sk https://localhost:7090/health             # Healthy
curl -sk https://localhost:7090/health/ready       # Healthy (the database answers)
curl -sk https://localhost:7090/.well-known/jwks.json   # {"keys":[{"kty":"EC",...,"kid":"signingkey1",...}]}
```

The `https` profile listens on `https://localhost:7090` and `http://localhost:5094`. Run
`dotnet dev-certs https --trust` once if your browser should open the API directly. The SPA's proxy does not need it.

`AccountEmail:*Url` and `OAuth:LoginUrl` must be https outside Development. `appsettings.Example.json` shows
`OAuth:LoginUrl` ending in `/signin`, but this SPA's page is `/login`.

## 5. Run the SPA

```bash
cd ../frontend
npm ci                                                       # lockfile install, install scripts disabled
npm run dev                                                  # http://localhost:5173, /api proxied to https://localhost:7090
```

The proxy targets the API's https URL by default (T29). To point it elsewhere, set `VITE_DEV_API_TARGET` in
`.env.local` (git-ignored). **Keep it https:** the API's plain-http port (`http://localhost:5094`) answers every
request with 500 in Development, because the antiforgery cookie requires HTTPS (T26 GAP-2).

Port 5173 is taken: run `npx vite --port 5174 --strictPort`, and use that origin in step 4's
`BrowserProtection:TrustedOrigins:0` and the three SPA URLs.

## 6. Sign up and create the first administrator

1. Open `http://localhost:5173/register` and create an account.
2. Open the newest `.eml` in the pickup directory and follow its `verify-email#token=...` link (the token is in
   the fragment).
3. Sign in at `/login`.
4. Make this account the first administrator, then restart the API:

   ```bash
   dotnet user-secrets set "Authorization:BootstrapAdminEmail" "you@example.com" --project src/Auth.Api
   ```

   The startup log says `bootstrap admin assigned: True`. **Sign in again**, or wait for the SPA's next silent refresh
   (up to 15 minutes). Then `/me` shows roles `Admin` and `User`, and `GET /api/v1/admin/users` answers 200.

   The two can disagree until then. `/me` builds the profile from the database, so it shows `Admin` at once. The admin
   policies check the `role` and `perm` claims in the access token, and those are minted only at sign-in or refresh.
   So, until a new token is minted, `/me` can show `Admin` while the admin API still answers 403
   ([authorization.md](authorization.md), "claims are read when the token is minted").
5. Remove the setting (`dotnet user-secrets remove "Authorization:BootstrapAdminEmail" --project src/Auth.Api`).
   It only applies while no active administrator exists, and later starts warn while it is set
   ([authorization.md](authorization.md)).

## 7. What the clean-clone check saw

Run on 2026-10-26 from a fresh `git clone` of `main` 94fd63c, with database `CentralAuth_T27Proof_Test`, kid
`proofkey1`, and the SPA on port 5174 (5173 was busy):

| Step | Result |
|---|---|
| `dotnet build Auth.sln` | 0 warnings, 0 errors |
| `dotnet ef database update` (DAL as startup) | 4 migrations (a fifth, `ClientApplicationListNames`, came in T29, a sixth, `ApplicationRolesRequireRole`, in T30), 14 tables (13 plus history) |
| key recipe and `sqlcmd -i` | 1 row, `Active`; JWKS lists `proofkey1` |
| API `https` profile | `/health` 200, `/health/ready` 200 |
| `npm ci`, `npm run build` | 138 packages; "19 files in dist/: no dev-only code" |
| through the Vite proxy (https target) | `GET /me` 401 (anonymous), register 202, verify-email 204, login 200, `/me` 200; cookies `__Host-access`, `__Secure-refresh`, `__Host-antiforgery`, `XSRF-TOKEN` |
| same, proxy on the old http default | `GET /me` 500 (GAP-2); the default is https since T29 |
| bootstrap admin and restart | `bootstrap admin assigned: True`; roles `Admin, User`; `/admin/users` 200 |

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Every API call through the SPA is 500 | The proxy targets plain http: `VITE_DEV_API_TARGET` in `.env.local` points at `http://...`. Use `https://localhost:7090`, or remove it (step 5). |
| POSTs answer 403 "Request origin is not allowed." | The SPA's origin is missing from `BrowserProtection:TrustedOrigins` (step 4). |
| "The private key of signing key ... was not found" | Wrong secret name, often a hyphen in an environment variable. See "Naming rule for secrets". |
| `/health/ready` 503 | The database does not answer: check the connection string and that `.\SQLEXPRESS` runs. |
| `dotnet ef` asks for Microsoft.EntityFrameworkCore.Design | Use `--startup-project src/Auth.DAL` (step 2). |
| The email link does not open | `AccountEmail:*Url` still https in Development. Use the http dev-server URLs (step 4). |
| Startup error about `AllowedHosts` | Outside Development it must list real host names, not `*` ([deployment.md](deployment.md)). |
