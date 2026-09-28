@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    trace = traceback.format_exc()
    try:
        audit_log(
            actor=request.session.get("user", "anonymous") if hasattr(request, "session") else "anonymous",
            actor_role=request.session.get("role", "unknown") if hasattr(request, "session") else "unknown",
            action="unhandled_exception",
            outcome="error",
            source_ip=request.client.host if request.client else "",
            details={"error": str(exc), "trace": trace[-4000:]},
        )
    except Exception:
        pass

    accept = (request.headers.get("accept") or "").lower()
    if "text/html" in accept:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "message": "An internal error occurred. Check audit logs."},
            status_code=500,
        )

    return RedirectResponse(url="/?error=Internal+server+error", status_code=303)


@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request, error: str = "") -> HTMLResponse:
    if has_users():
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("setup.html", {"request": request, "error": error})


@app.post("/setup")
async def setup_first_admin(
    request: Request,
    password: str = Form(...),
    confirm_password: str = Form(...),
) -> RedirectResponse:
    if has_users():
        return RedirectResponse(url="/login", status_code=303)

    pwd = password.strip()
    cpwd = confirm_password.strip()
    if not pwd or pwd != cpwd:
        return RedirectResponse(url="/setup?error=Passwords+do+not+match", status_code=303)

    salt_hex, digest_hex = hash_password(pwd)
    with closing(db_conn()) as conn:
        conn.execute(
            """
            INSERT INTO users (username, role, password_salt, password_hash, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("Admin", ROLE_ADMIN, salt_hex, digest_hex, utc_now_iso()),
        )
        conn.commit()

    request.session["user"] = "Admin"
    request.session["role"] = ROLE_ADMIN
    audit_log("Admin", ROLE_ADMIN, "first_admin_setup", "success", source_ip=request.client.host if request.client else "")
    return RedirectResponse(url="/", status_code=303)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = "") -> HTMLResponse:
    if not has_users():
        return RedirectResponse(url="/setup", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)) -> RedirectResponse:
    if not has_users():
        return RedirectResponse(url="/setup", status_code=303)

    ip = request.client.host if request.client else ""
    with closing(db_conn()) as conn:
        row = conn.execute(
            "SELECT username, role, password_salt, password_hash FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()

    if not row:
        audit_log(username.strip(), "unknown", "login", "failed", source_ip=ip)
        return RedirectResponse(url="/login?error=Invalid+credentials", status_code=303)

    if verify_password(password, row["password_salt"], row["password_hash"]):
        request.session["user"] = row["username"]
        request.session["role"] = row["role"]
        audit_log(row["username"], row["role"], "login", "success", source_ip=ip)
        return RedirectResponse(url="/", status_code=303)

    audit_log(row["username"], row["role"], "login", "failed", source_ip=ip)
    return RedirectResponse(url="/login?error=Invalid+credentials", status_code=303)


@app.post("/logout")
async def logout(request: Request) -> RedirectResponse:
    audit_log(request.session.get("user", "unknown"), request.session.get("role", "unknown"), "logout", "success", source_ip=request.client.host if request.client else "")
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


def _dashboard_fallback_html(request: Request, rows: List[Any], tenant_count: int, signin_count: int, alert_count: int, query: str, error: str, info: str = "") -> str:
    safe_rows = []
    for row in rows:
        safe_rows.append(
            "<tr>"
            f"<td>{html.escape(str(row['alerted_at'] or ''))}</td>"
            f"<td>{html.escape(str(row['customer_name'] or ''))}</td>"
            f"<td>{html.escape(str(row['tenant_id'] or ''))}</td>"
            f"<td>{html.escape(str(row['user_principal_name'] or ''))}</td>"
            f"<td>{html.escape(str(row['ip_address'] or ''))}</td>"
            f"<td>{html.escape(str(row['app_display_name'] or ''))}</td>"
            f"<td>{html.escape(str(row['severity'] or ''))}</td>"
            f"<td>{html.escape(str(row['reason'] or ''))}</td>"
            "</tr>"
        )

    rows_html = "".join(safe_rows) or '<tr><td colspan="8">No alerts found for the current filter.</td></tr>'
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>CodexSIEM Dashboard</title></head><body>"
        "<h1>Microsoft 365 Multi-Tenant SIEM</h1>"
        "<p><strong>Template warning:</strong> dashboard template failed to render. Showing fallback view.</p>"
        f"<p>Signed in as <strong>{html.escape(str(request.session.get('user', '')))}</strong> ({html.escape(str(request.session.get('role', '')))})</p>"
        + (f"<p style='color:#a00'>{html.escape(error)}</p>" if error else "")
        + (f"<p style='color:#0a5'>{html.escape(info)}</p>" if info else "")
        + f"<p>Tenants: {tenant_count} | Sign-ins: {signin_count} | Alerts: {alert_count}</p>"
        + "<form method='get' action='/'><input name='q' value='" + html.escape(query) + "' placeholder='Search' /> <button type='submit'>Search</button></form>"
        + "<table border='1' cellpadding='6' cellspacing='0'><thead><tr><th>Alert Time</th><th>Customer</th><th>Tenant</th><th>User</th><th>IP</th><th>Application</th><th>Severity</th><th>Reason</th></tr></thead><tbody>"
        + rows_html
        + "</tbody></table><p><a href='/tenants'>Connect M365 Tenant</a> | <a href='/users'>Manage Users</a> | <a href='/audit'>Audit Logs</a></p><form method='post' action='/check-updates'><button type='submit'>Check GitHub Updates</button></form></body></html>"
    )


def _tenants_fallback_html(request: Request, tenants: List[Any]) -> str:
    body_rows = []
    for t in tenants:
        body_rows.append(
            "<tr>"
            f"<td>{html.escape(str(t['customer_name'] or ''))}</td>"
            f"<td>{html.escape(str(t['name'] or ''))}</td>"
            f"<td>{html.escape(str(t['tenant_id'] or ''))}</td>"
            f"<td>{html.escape(str(t['client_id'] or ''))}</td>"
            f"<td>{html.escape(str(t['secret_source'] or ''))}</td>"
            f"<td>{html.escape(str(t['client_secret_ref'] or ''))}</td>"
            f"<td>{html.escape(str(t['created_at'] or ''))}</td>"
            "</tr>"
        )
    rows_html = "".join(body_rows) or '<tr><td colspan="6">No tenants configured yet.</td></tr>'
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Tenants</title></head><body>"
        "<h1>Manage M365 Tenants</h1>"
        "<p><strong>Template warning:</strong> tenants template failed to render. Showing fallback view.</p>"
        f"<p>Signed in as <strong>{html.escape(str(request.session.get('user', '')))}</strong> ({html.escape(str(request.session.get('role', '')))})</p>"
        "<p>You can still connect a Microsoft 365 tenant using this fallback form.</p>"
        "<form method='post' action='/tenants' style='display:grid;gap:8px;max-width:620px;margin-bottom:12px;'>"
        "<input name='customer_name' placeholder='Customer Name (e.g. Contoso Ltd)' required />"
        "<input name='name' placeholder='Connection Display Name' required />"
        "<input name='tenant_id' placeholder='Tenant ID (GUID)' required />"
        "<input name='client_id' placeholder='App Client ID' required />"
        "<input name='client_secret' placeholder='Client Secret Value or Secret ID (stored in DB)' />"
        "<div>or</div>"
        "<input name='client_secret_ref' placeholder='Env var name holding secret (e.g. TENANT_A_CLIENT_SECRET)' />"
        "<button type='submit'>Save Tenant</button>"
        "</form>"
        + "<table border='1' cellpadding='6' cellspacing='0'><thead><tr><th>Customer</th><th>Connection</th><th>Tenant ID</th><th>Client ID</th><th>Secret Source</th><th>Added</th></tr></thead><tbody>"
        "<input name='client_secret_ref' placeholder='Env var name holding secret (e.g. TENANT_A_CLIENT_SECRET)' required />"
        "<button type='submit'>Save Tenant</button>"
        "</form>"
        + "<table border='1' cellpadding='6' cellspacing='0'><thead><tr><th>Customer</th><th>Connection</th><th>Tenant ID</th><th>Client ID</th><th>Secret Env Var</th><th>Added</th></tr></thead><tbody>"
        + rows_html
        + "</tbody></table><p><a href='/'>Back to Dashboard</a></p></body></html>"
    )
