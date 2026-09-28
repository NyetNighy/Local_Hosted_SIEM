@app.post("/tenants")
async def create_tenant(
    request: Request,
    name: str = Form(...),
    customer_name: str = Form(...),
    tenant_id: str = Form(...),
    client_id: str = Form(...),
    client_secret_ref: str = Form(""),
    client_secret: str = Form(""),
) -> RedirectResponse:
    auth_redirect = require_manage_access(request)
    if auth_redirect:
        return auth_redirect

    secret_ref = client_secret_ref.strip()
    secret_value = client_secret.strip()
    if not secret_ref and not secret_value:
        return RedirectResponse(url="/tenants", status_code=303)

    secret_to_store = secret_value or ENV_REF_PLACEHOLDER

    with closing(db_conn()) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO tenants (name, customer_name, tenant_id, client_id, client_secret, client_secret_ref, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (name.strip(), customer_name.strip() or "Unassigned", tenant_id.strip(), client_id.strip(), secret_to_store, secret_ref, utc_now_iso()),
        )
        conn.commit()

    audit_log(request.session.get("user", "unknown"), request.session.get("role", "unknown"), "tenant_upsert", "success", target=tenant_id, source_ip=request.client.host if request.client else "", details={"customer_name": customer_name.strip() or "Unassigned"})
    return RedirectResponse(url="/tenants", status_code=303)


@app.post("/sync")
async def trigger_sync(request: Request) -> RedirectResponse:
    auth_redirect = require_manage_access(request)
    if auth_redirect:
        return auth_redirect

    results = await sync_all_tenants()
    audit_log(request.session.get("user", "unknown"), request.session.get("role", "unknown"), "sync", "success" if not results["errors"] else "partial", source_ip=request.client.host if request.client else "", details=results)
    return RedirectResponse(url="/", status_code=303)


@app.post("/check-updates")
async def check_updates(request: Request) -> RedirectResponse:
    auth_redirect = require_login(request)
    if auth_redirect:
        return auth_redirect

    status = check_github_update_status()
    audit_log(
        request.session.get("user", "unknown"),
        request.session.get("role", "unknown"),
        "check_updates",
        "success",
        source_ip=request.client.host if request.client else "",
        details={"status": status},
    )
    return RedirectResponse(url='/?info=' + httpx.QueryParams({'v': status})['v'], status_code=303)




@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request) -> HTMLResponse:
    auth_redirect = require_admin_access(request)
    if auth_redirect:
        return auth_redirect

    with closing(db_conn()) as conn:
        users = conn.execute("SELECT username, role, created_at FROM users ORDER BY created_at ASC").fetchall()

    return templates.TemplateResponse(
        "users.html",
        {
            "request": request,
            "users": users,
            "user": request.session.get("user", ""),
            "role": request.session.get("role", ""),
            "allowed_roles": sorted(ALLOWED_ROLES),
        },
    )


@app.post("/users")
async def create_or_update_user(
    request: Request,
    username: str = Form(...),
    role: str = Form(...),
    password: str = Form(...),
) -> RedirectResponse:
    auth_redirect = require_admin_access(request)
    if auth_redirect:
        return auth_redirect

    normalized_role = role.strip().lower()
    if normalized_role not in ALLOWED_ROLES:
        return RedirectResponse(url="/users", status_code=303)

    uname = username.strip()
    pwd = password.strip()
    if not uname or not pwd:
        return RedirectResponse(url="/users", status_code=303)

    salt_hex, digest_hex = hash_password(pwd)

    with closing(db_conn()) as conn:
        conn.execute(
            """
            INSERT INTO users (username, role, password_salt, password_hash, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                role=excluded.role,
                password_salt=excluded.password_salt,
                password_hash=excluded.password_hash
            """,
            (uname, normalized_role, salt_hex, digest_hex, utc_now_iso()),
        )
        conn.commit()

    audit_log(request.session.get("user", "unknown"), request.session.get("role", "unknown"), "user_upsert", "success", target=uname, source_ip=request.client.host if request.client else "", details={"assigned_role": normalized_role})
    return RedirectResponse(url="/users", status_code=303)


@app.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request) -> HTMLResponse:
    auth_redirect = require_admin_access(request)
    if auth_redirect:
        return auth_redirect

    with closing(db_conn()) as conn:
        logs = conn.execute(
            """
            SELECT event_time, actor, actor_role, action, target, outcome, source_ip, details
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 300
            """
        ).fetchall()

    return templates.TemplateResponse(
        "audit.html",
        {
            "request": request,
            "logs": logs,
            "user": request.session.get("user", ""),
            "role": request.session.get("role", ""),
        },
    )
