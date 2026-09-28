# Email alerting setup

CodexSIEM emails security alerts when new detections are written during **Sync Now**.

## 1. Enable and configure SMTP

```bash
export ALERT_EMAIL_ENABLED=true
export SMTP_HOST=smtp.office365.com
export SMTP_PORT=587
export SMTP_USE_TLS=true
export SMTP_USE_SSL=false
export SMTP_USER=siem-alerts@yourdomain.com
export SMTP_PASSWORD='your-app-password-or-secret'
export SMTP_FROM=siem-alerts@yourdomain.com
export SMTP_TO=soc@yourdomain.com,oncall@yourdomain.com
export ALERT_EMAIL_MIN_SEVERITY=medium
```

Restart the app after changing these variables.

| Variable | Purpose |
|----------|---------|
| `ALERT_EMAIL_ENABLED` | Master switch (`true` / `false`) |
| `SMTP_HOST` / `SMTP_PORT` | Mail server |
| `SMTP_USE_TLS` | STARTTLS (typical on port 587) |
| `SMTP_USE_SSL` | Implicit SSL (typical on port 465) |
| `SMTP_USER` / `SMTP_PASSWORD` | Auth (optional for some relays) |
| `SMTP_FROM` | From address |
| `SMTP_TO` | Comma-separated recipients |
| `ALERT_EMAIL_MIN_SEVERITY` | `low`, `medium`, or `high` |

## 2. Provider examples

### Microsoft 365

```bash
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USER=siem-alerts@yourdomain.com
SMTP_PASSWORD='...'
```

Ensure SMTP AUTH is allowed for that mailbox.

### Gmail (App Password)

```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USER=your@gmail.com
SMTP_PASSWORD='app-password'
SMTP_FROM=your@gmail.com
```

### SendGrid

```bash
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USER=apikey
SMTP_PASSWORD='SG....'
SMTP_FROM=siem@yourdomain.com
```

## 3. Verify

1. Sign in as **admin**.
2. Open **Email** (`/settings/email`).
3. Confirm **Ready = yes**.
4. Click **Send test email**.

## 4. When emails are sent

On each sync, **new** alerts trigger HTML + plain-text email if severity ≥ `ALERT_EMAIL_MIN_SEVERITY`. Failures are logged and do not stop ingestion.
