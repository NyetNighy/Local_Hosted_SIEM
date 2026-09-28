def _alert_filter_clauses(
    q: str = "",
    customer: str = "",
    group: str = "",
    tenant: str = "",
    severity: str = "",
    user: str = "",
    ip: str = "",
    app: str = "",
    reason: str = "",
    date_from: str = "",
    date_to: str = "",
    for_signins: bool = False,
) -> tuple:
    """Build WHERE clause + params for alert (or signin) queries.

    for_signins=True omits alert-only columns (severity/reason) and uses s-only joins.
    """
    where_parts: List[str] = []
    params: List[Any] = []

    customer_f = customer.strip()
    group_f = group.strip()
    tenant_f = tenant.strip()
    severity_f = severity.strip().lower()
    user_f = user.strip()
    ip_f = ip.strip()
    app_f = app.strip()
    reason_f = reason.strip()
    date_from_f = date_from.strip()
    date_to_f = date_to.strip()
    query = q.strip()

    if customer_f:
        where_parts.append("t.customer_name = ?")
        params.append(customer_f)
    if group_f:
        where_parts.append("COALESCE(t.customer_group, '') = ?")
        params.append(group_f)
    if tenant_f:
        where_parts.append("s.tenant_id = ?")
        params.append(tenant_f)
    if user_f:
        where_parts.append("s.user_principal_name LIKE ?")
        params.append(f"%{user_f}%")
    if ip_f:
        where_parts.append("s.ip_address LIKE ?")
        params.append(f"%{ip_f}%")
    if app_f:
        where_parts.append("s.app_display_name LIKE ?")
        params.append(f"%{app_f}%")
    if not for_signins:
        if severity_f:
            where_parts.append("LOWER(a.severity) = ?")
            params.append(severity_f)
        if reason_f:
            where_parts.append("a.reason LIKE ?")
            params.append(f"%{reason_f}%")
        if date_from_f:
            where_parts.append("a.created_at >= ?")
            params.append(date_from_f)
        if date_to_f:
            where_parts.append("a.created_at <= ?")
            params.append(date_to_f + "T23:59:59.999999")
    else:
        if date_from_f:
            where_parts.append("s.created_at >= ?")
            params.append(date_from_f)
        if date_to_f:
            where_parts.append("s.created_at <= ?")
            params.append(date_to_f + "T23:59:59.999999")

    if query:
        where_parts.append(
            "(s.tenant_id LIKE ? OR t.customer_name LIKE ? OR COALESCE(t.customer_group, '') LIKE ? "
            "OR t.name LIKE ? OR s.user_principal_name LIKE ? OR s.ip_address LIKE ? OR s.app_display_name LIKE ?"
            + ("" if for_signins else " OR a.reason LIKE ? OR a.severity LIKE ?")
            + ")"
        )
        term = f"%{query}%"
        params.extend([term, term, term, term, term, term, term])
        if not for_signins:
            params.extend([term, term])

    filters = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
    cleaned = {
        "q": query,
        "customer": customer_f,
        "group": group_f,
        "tenant": tenant_f,
        "severity": severity_f,
        "user": user_f,
        "ip": ip_f,
        "app": app_f,
        "reason": reason_f,
        "date_from": date_from_f,
        "date_to": date_to_f,
    }
    return filters, params, cleaned


@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    q: str = "",
    customer: str = "",
    group: str = "",
    tenant: str = "",
    severity: str = "",
    user: str = "",
    ip: str = "",
    app: str = "",
    reason: str = "",
    date_from: str = "",
    date_to: str = "",
    error: str = "",
    info: str = "",
) -> HTMLResponse:
    auth_redirect = require_login(request)
    if auth_redirect:
        return auth_redirect

    filters, params, cleaned = _alert_filter_clauses(
        q=q, customer=customer, group=group, tenant=tenant,
        severity=severity, user=user, ip=ip, app=app, reason=reason,
        date_from=date_from, date_to=date_to, for_signins=False,
    )
    s_filters, s_params, _ = _alert_filter_clauses(
        q=q, customer=customer, group=group, tenant=tenant,
        severity="", user=user, ip=ip, app=app, reason="",
        date_from=date_from, date_to=date_to, for_signins=True,
    )

    with closing(db_conn()) as conn:
        tenant_count = conn.execute("SELECT COUNT(*) FROM tenants").fetchone()[0]
        if s_filters:
            signin_count = conn.execute(
                f"""
                SELECT COUNT(*) FROM signins s
                JOIN tenants t ON t.tenant_id = s.tenant_id
                {s_filters}
                """,
                s_params,
            ).fetchone()[0]
        else:
            signin_count = conn.execute("SELECT COUNT(*) FROM signins").fetchone()[0]

        if filters:
            alert_count = conn.execute(
                f"""
                SELECT COUNT(*) FROM alerts a
                JOIN signins s ON s.graph_id = a.signins_graph_id AND s.tenant_id = a.tenant_id
                JOIN tenants t ON t.tenant_id = s.tenant_id
                {filters}
                """,
                params,
            ).fetchone()[0]
        else:
            alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

        rows = conn.execute(
            f"""
            SELECT a.created_at AS alerted_at, a.severity, a.reason,
                   s.tenant_id, t.customer_name, COALESCE(t.customer_group, '') AS customer_group,
                   t.name AS connection_name,
                   s.user_principal_name, s.ip_address,
                   s.app_display_name, s.created_at AS signin_time,
                   s.status_error_code, s.status_failure_reason
            FROM alerts a
            JOIN signins s ON s.graph_id = a.signins_graph_id AND s.tenant_id = a.tenant_id
            JOIN tenants t ON t.tenant_id = s.tenant_id
            {filters}
            ORDER BY a.created_at DESC
            LIMIT 500
            """,
            params,
        ).fetchall()

        customers = [
            r[0]
            for r in conn.execute(
                "SELECT DISTINCT customer_name FROM tenants WHERE TRIM(customer_name) <> '' ORDER BY customer_name ASC"
            ).fetchall()
        ]
        groups = [
            r[0]
            for r in conn.execute(
                "SELECT DISTINCT customer_group FROM tenants WHERE COALESCE(TRIM(customer_group), '') <> '' ORDER BY customer_group ASC"
            ).fetchall()
        ]
        tenancies = conn.execute(
            """
            SELECT tenant_id, customer_name, name, COALESCE(customer_group, '') AS customer_group
            FROM tenants
            ORDER BY customer_name ASC, name ASC
            """
        ).fetchall()
        severities = [
            r[0]
            for r in conn.execute(
                "SELECT DISTINCT LOWER(severity) FROM alerts WHERE severity IS NOT NULL ORDER BY 1"
            ).fetchall()
        ]

    role = request.session.get("role", "")
    export_qs = httpx.QueryParams({k: v for k, v in cleaned.items() if v})
    try:
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "tenant_count": tenant_count,
                "signin_count": signin_count,
                "alert_count": alert_count,
                "alerts": rows,
                **cleaned,
                "customers": customers,
                "groups": groups,
                "tenancies": tenancies,
                "severities": severities or ["high", "medium", "low"],
                "export_qs": str(export_qs),
                "error": error,
                "info": info,
                "user": request.session.get("user", ""),
                "role": role,
                "can_manage": user_can_manage(role),
                "is_admin": user_is_admin(role),
                "filter_user": cleaned["user"],
            },
        )
    except Exception:
        LOGGER.exception("Failed to render dashboard.html; returning fallback dashboard HTML")
        return HTMLResponse(
            _dashboard_fallback_html(
                request, rows, tenant_count, signin_count, alert_count, cleaned["q"], error, info
            ),
            status_code=200,
        )


@app.get("/export/alerts.csv")
async def export_alerts_csv(
    request: Request,
    q: str = "",
    customer: str = "",
    group: str = "",
    tenant: str = "",
    severity: str = "",
    user: str = "",
    ip: str = "",
    app: str = "",
    reason: str = "",
    date_from: str = "",
    date_to: str = "",
) -> StreamingResponse:
    auth_redirect = require_login(request)
    if auth_redirect:
        return StreamingResponse(iter(["Unauthorized"]), status_code=401)

    filters, params, _ = _alert_filter_clauses(
        q=q, customer=customer, group=group, tenant=tenant,
        severity=severity, user=user, ip=ip, app=app, reason=reason,
        date_from=date_from, date_to=date_to, for_signins=False,
    )

    with closing(db_conn()) as conn:
        rows = conn.execute(
            f"""
            SELECT a.created_at AS alerted_at, t.customer_name, COALESCE(t.customer_group, '') AS customer_group,
                   s.tenant_id, t.name AS connection_name,
                   s.user_principal_name, s.ip_address, s.app_display_name,
                   s.created_at AS signin_time, a.severity, a.reason,
                   s.status_error_code, s.status_failure_reason
            FROM alerts a
            JOIN signins s ON s.graph_id = a.signins_graph_id AND s.tenant_id = a.tenant_id
            JOIN tenants t ON t.tenant_id = s.tenant_id
            {filters}
            ORDER BY a.created_at DESC
            LIMIT 10000
            """,
            params,
        ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "alerted_at", "customer_name", "customer_group", "tenant_id", "connection_name",
        "user_principal_name", "ip_address", "app_display_name", "signin_time",
        "severity", "reason", "status_error_code", "status_failure_reason",
    ])
    for row in rows:
        writer.writerow([
            row["alerted_at"], row["customer_name"], row["customer_group"], row["tenant_id"],
            row["connection_name"], row["user_principal_name"], row["ip_address"],
            row["app_display_name"], row["signin_time"], row["severity"], row["reason"],
            row["status_error_code"], row["status_failure_reason"],
        ])

    csv_data = output.getvalue()
    output.close()
    headers = {"Content-Disposition": "attachment; filename=codexsiem_alerts.csv"}
    return StreamingResponse(iter([csv_data]), media_type="text/csv", headers=headers)



@app.get("/tenants", response_class=HTMLResponse)
async def tenant_page(request: Request) -> HTMLResponse:
    auth_redirect = require_manage_access(request)
    if auth_redirect:
        return auth_redirect

    with closing(db_conn()) as conn:
        tenants = conn.execute(
            """
            SELECT
                name,
                customer_name,
                COALESCE(customer_group, '') AS customer_group,
                tenant_id,
                client_id,
                client_secret_ref,
                client_secret,
                CASE
                    WHEN COALESCE(TRIM(client_secret_ref), '') <> '' THEN 'Env Var: ' || client_secret_ref
                    WHEN COALESCE(TRIM(client_secret), '') <> '' AND client_secret <> ? THEN 'Stored in DB'
                    ELSE 'Not configured'
                END AS secret_source,
                created_at
            FROM tenants
            ORDER BY customer_group ASC, customer_name ASC, name ASC
            """,
            (ENV_REF_PLACEHOLDER,),
        ).fetchall()
    try:
        return templates.TemplateResponse(
            "tenants.html",
            {
                "request": request,
                "tenants": tenants,
                "user": request.session.get("user", ""),
                "role": request.session.get("role", ""),
            },
        )
    except Exception:
        LOGGER.exception("Failed to render tenants.html; returning fallback tenants HTML")
        return HTMLResponse(_tenants_fallback_html(request, tenants), status_code=200)
