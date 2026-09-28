# CodexSIEM

A lightweight **multi-tenant Microsoft 365 SIEM** that:

- Connects to multiple M365 tenancies (each with its own Entra app credentials)
- Pulls sign-in logs from Microsoft Graph (`auditLogs/signIns`)
- Generates alerts for suspicious sign-ins (failed attempts, risk, conditional access, legacy auth, high-risk countries, impossible travel)
- Groups data by **customer**, **group**, and **M365 tenancy**
- Provides a modern dark UI with sidebar navigation, dense tables, and sticky column headers
- Supports advanced search/filters and CSV export
- Sends optional **SMTP email alerts** (HTML + plain text) with severity gating
- Includes role-based access control (**admin** / **manager** / **user**), audit logs, and optional SSO/MFA via reverse-proxy headers

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export SIEM_SESSION_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
# Local demo only (skip if you set a real secret above):
# export SIEM_ALLOW_INSECURE=true

python run_server.py --host 0.0.0.0 --port 8000
```

Open: **http://localhost:8000** (not `0.0.0.0`).

On first run with no users, you are redirected to `/setup` to create the initial **Admin** account.

Alternative entrypoints:

```bash
python scripts/run_server.py --host 0.0.0.0 --port 8000
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Session cookies

| Environment | Setting |
|-------------|---------|
| Local HTTP | `SIEM_SESSION_HTTPS_ONLY=false` (default) |
| HTTPS / reverse proxy | `SIEM_SESSION_HTTPS_ONLY=true` |

Secure-only cookies on plain HTTP can cause login loops.

## Features

### Dashboard & search

Filter and search alerts by:

| Filter | Description |
|--------|-------------|
| **From / To date** | Alert time range |
| **Severity** | low / medium / high |
| **User (UPN)** | Sign-in user principal name |
| **Customer** | Customer name on the tenant connection |
| **Group** | Customer group / business unit |
| **M365 tenancy** | Exact tenant ID |
| **IP address** | Partial match |
| **Application** | App display name |
| **Reason** | Alert reason text |
| **Quick search** | Free text across user, IP, app, reason, tenant, customer |

Filters combine with **AND**. Stats and **Export CSV** respect the same filters.

### Customer / group / tenancy

Each tenant connection can store:

- **Customer name** — client/account (e.g. `Contoso Ltd`)
- **Customer group** — optional grouping (e.g. `EMEA`, `MSP-A`)
- **Connection display name** — internal label (e.g. `Contoso-Prod-M365`)
- **Tenant ID** — M365 directory ID

Use **Manage Tenants** to set these. Dashboard filters and tables expose all of them.

### Email alerting

When enabled, each **new** alert during sync can send a multipart email (plain text + HTML).

```bash
export ALERT_EMAIL_ENABLED=true
export SMTP_HOST=smtp.office365.com
export SMTP_PORT=587
export SMTP_USE_TLS=true
export SMTP_USER=siem-alerts@yourdomain.com
export SMTP_PASSWORD='...'
export SMTP_FROM=siem-alerts@yourdomain.com
export SMTP_TO=soc@yourdomain.com,oncall@yourdomain.com
export ALERT_EMAIL_MIN_SEVERITY=medium   # low | medium | high
```

- Admin UI: **Email** → `/settings/email` (status + **Send test email**)
- Full guide: [`docs/email-alerting.md`](docs/email-alerting.md)

Email failures are logged and do not stop sign-in ingestion.

### Detection rules

- Failed sign-ins
- Sign-in risk levels
- Conditional access failures / not applied
- Legacy auth (IMAP/POP/SMTP/EAS/other clients)
- High-risk country codes (`RU`, `KP`, `IR`)
- Simple impossible-travel heuristic (country change within 60 minutes)

### Roles (RBAC)

| Role | Access |
|------|--------|
| **admin** | Dashboard, sync, tenants, users, audit, email settings |
| **manager** | Dashboard, sync, tenants |
| **user** | Dashboard / search (read-only) |

### Audit logging

Structured records for login, SSO, logout, tenant/user changes, sync, and email test. View at `/audit` (admin).

## Microsoft 365 tenant setup

1. Register an app in each tenant and grant **application** permissions:
   - `AuditLog.Read.All`
   - `Directory.Read.All` (optional enrichment)
2. Grant admin consent.
3. Store **Tenant ID**, **Client ID**, and a **client secret** (preferably in env vars).
4. In the UI: **Tenants** → add connection; set `client_secret_ref` to the env var name (e.g. `TENANT_A_CLIENT_SECRET`).

Detailed walkthrough: [`docs/m365-app-setup.md`](docs/m365-app-setup.md) · [`docs/m365-setup.md`](docs/m365-setup.md)

```bash
export TENANT_A_CLIENT_SECRET='super-secret-value'
```

## Environment reference

See [`.env.example`](.env.example). Important variables:

| Variable | Purpose |
|----------|---------|
| `SIEM_SESSION_SECRET` | Required in production (long random string) |
| `SIEM_ALLOW_INSECURE` | Allow default session secret for local demos only |
| `SIEM_DB_PATH` | SQLite path (default `siem.db`) |
| `SIEM_SYNC_MINUTES` | Graph lookback window (default `15`) |
| `SIEM_SESSION_HTTPS_ONLY` | Secure cookie flag |
| `ALERT_EMAIL_*` / `SMTP_*` | Email alerting (see above) |
| `OPENCLAWAI_*` | Optional webhook forwarding |
| `SIEM_SSO_*` | Optional reverse-proxy SSO/MFA headers |
| `SIEM_GITHUB_REPO` | Optional update-check target |

## Sync

- **Sync Now** on the dashboard fetches recent sign-ins for all configured tenants.
- Default lookback: 15 minutes (`SIEM_SYNC_MINUTES`).
- Data stored in SQLite.

## CSV export

**Export CSV** downloads the current filtered alert set as `codexsiem_alerts.csv`.

Endpoint: `/export/alerts.csv` (supports the same query parameters as the dashboard).

## Optional integrations

### OpenClawAI webhook

```bash
export OPENCLAWAI_ENABLED=true
export OPENCLAWAI_URL=https://your-openclawai.example/api/alerts
export OPENCLAWAI_API_KEY=...   # optional
```

See [`docs/openclawai-integration.md`](docs/openclawai-integration.md).

### SSO / MFA via reverse proxy

```bash
export SIEM_SSO_ENABLED=true
export SIEM_SSO_USER_HEADER=X-Auth-Request-User
export SIEM_SSO_ROLE_HEADER=X-Auth-Request-Role
export SIEM_SSO_MFA_HEADER=X-Auth-Request-Amr
export SIEM_SSO_REQUIRE_MFA=true
```

## Production notes

1. Put the app behind a reverse proxy with TLS (Nginx, Traefik, Caddy, or cloud LB).
2. Expose only HTTPS; do not expose plain HTTP directly.
3. Restrict source IPs where possible (office/VPN).
4. Use a strong `SIEM_SESSION_SECRET` and rotate it periodically.
5. Keep tenant client secrets in env vars or a secret manager (not in the DB as plaintext for new tenants).
6. External access guide: [`docs/external-access.md`](docs/external-access.md).

## Troubleshooting

### `ModuleNotFoundError: No module named 'itsdangerous'`

```bash
source .venv/bin/activate
pip install -r requirements.txt
python scripts/verify_runtime.py
```

If needed, recreate the venv:

```bash
deactivate || true
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Startup / entrypoint issues

Prefer the root wrapper:

```bash
python run_server.py --host 0.0.0.0 --port 8000
```

Auto-recover from git if files look corrupted:

```bash
python run_server.py --auto-recover --host 0.0.0.0 --port 8000
# or
python scripts/repair_entrypoints.py --include-application
```

### PR merge conflicts

See [`docs/pr-conflicts.md`](docs/pr-conflicts.md).

## Project layout (high level)

```
codexsiem/          # config, db, detection, graph, notifications, routes
templates/          # Jinja2 UI (base layout, dashboard, tenants, email, …)
docs/               # setup guides
scripts/            # run/verify/repair helpers
application.py      # FastAPI app + sync/alert pipeline
run_server.py       # preferred launcher
```

## License

See [LICENSE](LICENSE).
