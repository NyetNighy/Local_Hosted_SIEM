@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    q: str = "",
    customer: str = "",
    group: str = "",
    tenant: str = "",
    error: str = "",
    info: str = "",
) -> HTMLResponse:
    auth_redirect = require_login(request)
    if auth_redirect:
        return auth_redirect

    query = q.strip()
    customer_f = customer.strip()
    group_f = group.strip()
    tenant_f = tenant.strip()

    with closing(db_conn()) as conn:
        where_parts: List[str] = []
        params: List[Any] = []

        if customer_f:
            where_parts.append("t.customer_name = ?")
            params.append(customer_f)
        if group_f:
            where_parts.append("COALESCE(t.customer_group, '') = ?")
            params.append(group_f)
        if tenant_f:
            where_parts.append("s.tenant_id = ?")
            params.append(tenant_f)
        if query:
            where_parts.append(
                "(s.tenant_id LIKE ? OR t.customer_name LIKE ? OR COALESCE(t.customer_group, '') LIKE ? "
                "OR t.name LIKE ? OR s.user_principal_name LIKE ? OR s.ip_address LIKE ? OR s.app_display_name LIKE ?)"
            )
            term = f"%{query}%"
            params.extend([term, term, term, term, term, term, term])

        filters = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

        tenant_count = conn.execute("SELECT COUNT(*) FROM tenants").fetchone()[0]
        if filters:
            signin_count = conn.execute(
                f"""
                SELECT COUNT(*) FROM signins s
                JOIN tenants t ON t.tenant_id = s.tenant_id
                {filters}
                """,
                params,
            ).fetchone()[0]
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
            signin_count = conn.execute("SELECT COUNT(*) FROM signins").fetchone()[0]
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
            LIMIT 200
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

    role = request.session.get("role", "")
    export_qs = httpx.QueryParams({
        k: v for k, v in {
            "q": query,
            "customer": customer_f,
            "group": group_f,
            "tenant": tenant_f,
        }.items() if v
    })
    try:
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "tenant_count": tenant_count,
                "signin_count": signin_count,
                "alert_count": alert_count,
                "alerts": rows,
                "q": query,
                "customer": customer_f,
                "group": group_f,
                "tenant": tenant_f,
                "customers": customers,
                "groups": groups,
                "tenancies": tenancies,
                "export_qs": str(export_qs),
                "error": error,
                "info": info,
                "user": request.session.get("user", ""),
                "role": role,
                "can_manage": user_can_manage(role),
                "is_admin": user_is_admin(role),
            },
        )
    except Exception:
        LOGGER.exception("Failed to render dashboard.html; returning fallback dashboard HTML")
        return HTMLResponse(
            _dashboard_fallback_html(request, rows, tenant_count, signin_count, alert_count, query, error, info),
            status_code=200,
        )


@app.get("/export/alerts.csv")
async def export_alerts_csv(
    request: Request,
    q: str = "",
    customer: str = "",
    group: str = "",
    tenant: str = "",
) -> StreamingResponse:
    auth_redirect = require_login(request)
    if auth_redirect:
        return StreamingResponse(iter(["Unauthorized"]), status_code=401)

    query = q.strip()
    customer_f = customer.strip()
    group_f = group.strip()
    tenant_f = tenant.strip()

    with closing(db_conn()) as conn:
        where_parts: List[str] = []
        params: List[Any] = []
        if customer_f:
            where_parts.append("t.customer_name = ?")
            params.append(customer_f)
        if group_f:
            where_parts.append("COALESCE(t.customer_group, '') = ?")
            params.append(group_f)
        if tenant_f:
            where_parts.append("s.tenant_id = ?")
            params.append(tenant_f)
        if query:
            where_parts.append(
                "(s.tenant_id LIKE ? OR t.customer_name LIKE ? OR COALESCE(t.customer_group, '') LIKE ? "
                "OR t.name LIKE ? OR s.user_principal_name LIKE ? OR s.ip_address LIKE ? OR s.app_display_name LIKE ?)"
            )
            term = f"%{query}%"
            params.extend([term, term, term, term, term, term, term])
        filters = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

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
            LIMIT 5000
            """,
            params,
        ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "alerted_at",
        "customer_name",
        "customer_group",
        "tenant_id",
        "connection_name",
        "user_principal_name",
        "ip_address",
        "app_display_name",
        "signin_time",
        "severity",
        "reason",
        "status_error_code",
        "status_failure_reason",
    ])
    for row in rows:
        writer.writerow([
            row["alerted_at"],
            row["customer_name"],
            row["customer_group"],
            row["tenant_id"],
            row["connection_name"],
            row["user_principal_name"],
            row["ip_address"],
            row["app_display_name"],
            row["signin_time"],
            row["severity"],
            row["reason"],
            row["status_error_code"],
            row["status_failure_reason"],
        ])

    csv_data = output.getvalue()
    output.close()

    filename = "codexsiem_alerts.csv"
    headers = {"Content-Disposition": f"attachment; filename={filename}"}
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
