# Entra Tenant Security Auditor

A C++17 command-line tool that authenticates to **Microsoft Graph** with a hand-written OAuth2
client-credentials flow and audits a Microsoft Entra ID tenant. It reports findings tagged
**HIGH / MEDIUM / LOW**, each with a one-line "why this matters", to the console, a CSV and an HTML page.

> **Lab use only.** It is built and tested against a personal lab tenant with deliberately
> seeded misconfigurations. A built-in guardrail refuses to run against any other tenant.

## What it checks

| Check | Graph endpoint | Status |
|---|---|---|
| Users with no MFA method registered | `/users/{id}/authentication/methods` | tested on lab tenant |
| Accounts holding privileged directory roles | `/roleManagement/directory/roleAssignments` | tested on lab tenant |
| Guest / external accounts | `/users` (`userType`, `externalUserState`) | logic tested; needs a guest in the lab |
| Conditional Access: enforced vs report-only, exclusions | `/identity/conditionalAccess/policies` | analysis unit-tested on fake data; **not yet run against Graph** |
| Intune: non-compliant and 30+ day stale devices | `/deviceManagement/managedDevices` | analysis unit-tested on fake data; **not yet run against Graph** |

Cross-checks: a no-MFA finding on an account that also holds a privileged role is escalated to HIGH.
A module that cannot run (missing licence or permission) is listed as **NOT AUDITED** in the console
and HTML report instead of silently disappearing.

## Sample output

Sanitised output from the lab tenant (names and IDs replaced), see [docs/sample-output.txt](docs/sample-output.txt).

## How authentication works

```
POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
grant_type=client_credentials & client_id & client_secret & scope=https://graph.microsoft.com/.default
```

The reply contains a bearer token. Every Graph call sends `Authorization: Bearer <token>`.
There is no user and no browser: the app acts as itself using **application permissions**, so
what an admin consented to in the portal is the hard limit of what the tool can read.

## Least-privilege permissions (Application, read-only)

| Permission | Why |
|---|---|
| `User.Read.All` | list users, detect guests |
| `UserAuthenticationMethod.Read.All` | see which MFA methods each user registered |
| `RoleManagement.Read.Directory` | role definitions and assignments (narrower than `Directory.Read.All`) |
| `Policy.Read.All` | Conditional Access policies |
| `DeviceManagementManagedDevices.Read.All` | Intune device compliance and last check-in |

No `*.ReadWrite.*` permission is ever needed, and the tool refuses to run if its token holds one.

## Safety design

- **Tenant guardrail:** the token's `tid` claim must equal `ENTRA_LAB_TENANT_ID`, otherwise the tool stops before any audit call.
- **Read-only enforcement:** refuses to run if the token carries any permission containing `Write`.
- **Secrets:** the client secret is read from an environment variable only; nothing secret is written to disk or committed. `reports/` is git-ignored because real reports contain tenant data.
- **Output escaping:** tenant-controlled text is HTML-escaped, and CSV cells starting with `= + - @` are neutralised (CSV injection).
- **Unverified JWT read:** the token is decoded only to decide whether to *refuse*; it came directly from Microsoft over TLS.

## Build

Requirements: a C++17 compiler, CMake 3.21+, Ninja, and [vcpkg](https://github.com/microsoft/vcpkg) (libcurl and nlohmann/json are installed by the manifest, `vcpkg.json`).

```bash
export VCPKG_ROOT=$HOME/vcpkg
cmake --preset default
cmake --build build
ctest --test-dir build --output-on-failure
```

## Run

Register an app in **your own lab tenant**, add the application permissions above, grant admin consent, and create a client secret.

```bash
export ENTRA_TENANT_ID="<tenant id>"
export ENTRA_LAB_TENANT_ID="<same id: the one tenant this tool may touch>"
export ENTRA_CLIENT_ID="<app client id>"
read -rs "?Paste secret: " ENTRA_CLIENT_SECRET && export ENTRA_CLIENT_SECRET   # zsh; not saved to history
./build/entra_auditor        # writes reports/audit.csv and reports/audit.html
```

## Layout

```
src/http.*      libcurl wrapper (RAII handle, write callback, GET/POST)
src/token.*     OAuth2 client-credentials token request
src/graph.*     GET with bearer token, follows @odata.nextLink paging
src/guard.*     tenant + read-only guardrail (JWT payload decode)
src/audit.*     the audit modules; analyse_* functions are pure and unit-tested
src/report.*    CSV and HTML output
src/time_util.* ISO-8601 UTC parser (calendar maths, no platform-specific calls)
tests/          dependency-free unit tests
```

## Limitations

- One Graph request per user for MFA methods (no `$batch` yet).
- The privileged-role list is maintained in code because `isPrivileged` exists only in Graph beta.
- Eligible (PIM) role assignments are not covered yet.
- Excluded groups, roles and apps in Conditional Access are shown as IDs, not names.

## Lab setup screenshots

_To be added: lab tenant, app registration permissions, seeded misconfigurations, HTML report._
