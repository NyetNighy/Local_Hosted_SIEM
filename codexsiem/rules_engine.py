"""YAML-driven detection rules engine for Graph sign-in events."""
from __future__ import annotations

import logging
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

LOGGER = logging.getLogger(__name__)

_TEMPLATE_RE = re.compile(r"\{\{\s*([\w.]+)\s*\}\}")

# Cached ruleset
_ruleset: Optional[Dict[str, Any]] = None
_rules_path: Optional[Path] = None


def _parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def get_path(obj: Any, path: str) -> Any:
    """Resolve dotted path against a nested dict (Graph sign-in JSON)."""
    if not path:
        return None
    cur: Any = obj
    for part in path.split("."):
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _norm_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def eval_condition(signin: Dict[str, Any], cond: Dict[str, Any], lists: Dict[str, List[Any]]) -> bool:
    if not isinstance(cond, dict):
        return False

    if "all" in cond:
        return all(eval_condition(signin, c, lists) for c in cond["all"])
    if "any" in cond:
        return any(eval_condition(signin, c, lists) for c in cond["any"])

    field = cond.get("field") or ""
    op = (cond.get("op") or "eq").lower()
    raw = get_path(signin, field)

    if op == "exists":
        return raw is not None and _norm_str(raw) != ""
    if op == "not_exists":
        return raw is None or _norm_str(raw) == ""

    value = cond.get("value")

    if op in {"eq", "ne"}:
        left = raw
        right = value
        # numeric-friendly compare when both look like ints
        try:
            if left is not None and right is not None:
                left_n = int(left)
                right_n = int(right)
                left, right = left_n, right_n
        except (TypeError, ValueError):
            left = _norm_str(left).lower()
            right = _norm_str(right).lower()
        ok = left == right
        return ok if op == "eq" else not ok

    if op == "in":
        candidates = [_norm_str(v).lower() for v in _as_list(value)]
        return _norm_str(raw).lower() in candidates

    if op == "not_in":
        candidates = [_norm_str(v).lower() for v in _as_list(value)]
        return _norm_str(raw).lower() not in candidates

    if op == "in_list":
        list_name = cond.get("list") or ""
        entries = lists.get(list_name) or []
        # country lists: uppercase; client lists: lowercase
        needle = _norm_str(raw)
        upper_entries = {_norm_str(e).upper() for e in entries}
        lower_entries = {_norm_str(e).lower() for e in entries}
        return needle.upper() in upper_entries or needle.lower() in lower_entries

    if op == "contains":
        return _norm_str(value).lower() in _norm_str(raw).lower()

    if op == "regex":
        try:
            return re.search(str(value), _norm_str(raw), re.IGNORECASE) is not None
        except re.error:
            return False

    if op in {"gt", "gte", "lt", "lte"}:
        try:
            left = float(raw)
            right = float(value)
        except (TypeError, ValueError):
            return False
        if op == "gt":
            return left > right
        if op == "gte":
            return left >= right
        if op == "lt":
            return left < right
        return left <= right

    LOGGER.warning("Unknown rule op: %s", op)
    return False


def render_reason(template: str, signin: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> str:
    extra = extra or {}

    def repl(match: re.Match) -> str:
        key = match.group(1)
        if key.startswith("correlate."):
            val = extra.get(key.split(".", 1)[1])
            return "" if val is None else str(val)
        val = get_path(signin, key)
        if val is None and key in extra:
            val = extra[key]
        return "" if val is None else str(val)

    return _TEMPLATE_RE.sub(repl, template or "")


def load_ruleset(path: Path, force: bool = False) -> Dict[str, Any]:
    global _ruleset, _rules_path
    if _ruleset is not None and _rules_path == path and not force:
        return _ruleset

    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required for detection rules. pip install PyYAML") from exc

    if not path.is_file():
        raise FileNotFoundError(f"Detection rules file not found: {path}")

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("Rules file root must be a mapping")

    defaults = data.get("defaults") or {}
    lists = data.get("lists") or {}
    rules = data.get("rules") or []
    if not isinstance(rules, list):
        raise ValueError("'rules' must be a list")

    seen = set()
    normalized: List[Dict[str, Any]] = []
    for raw in rules:
        if not isinstance(raw, dict):
            continue
        rid = (raw.get("id") or "").strip()
        if not rid:
            LOGGER.warning("Skipping rule without id")
            continue
        if rid in seen:
            LOGGER.warning("Duplicate rule id skipped: %s", rid)
            continue
        seen.add(rid)
        enabled = raw.get("enabled", defaults.get("enabled", True))
        if enabled is False:
            continue
        rule = {
            "id": rid,
            "name": raw.get("name") or rid,
            "severity": (raw.get("severity") or defaults.get("severity") or "medium").lower(),
            "group": raw.get("group") or "",
            "tags": list(raw.get("tags") or []),
            "mitre": list(raw.get("mitre") or []),
            "notify": bool(raw.get("notify", defaults.get("notify", True))),
            "reason": raw.get("reason") or raw.get("name") or rid,
            "match": raw.get("match"),
            "correlate": raw.get("correlate"),
        }
        if not rule["match"] and not rule["correlate"]:
            LOGGER.warning("Rule %s has neither match nor correlate; skipped", rid)
            continue
        normalized.append(rule)

    _ruleset = {"version": data.get("version"), "lists": lists, "rules": normalized, "path": str(path)}
    _rules_path = path
    LOGGER.info("Loaded %d detection rules from %s", len(normalized), path)
    return _ruleset


def reload_ruleset(path: Path) -> Dict[str, Any]:
    return load_ruleset(path, force=True)


def _failed_burst_count(
    conn: sqlite3.Connection,
    tenant_id: str,
    upn: str,
    window_minutes: int,
    current_time: Optional[datetime],
) -> int:
    """Count failed sign-ins for user in window (including current row if already inserted)."""
    if not upn:
        return 0
    # Prefer explicit window relative to event time when available
    if current_time is not None:
        # SQLite stores ISO strings; compare lexicographically for Z/offset times is imperfect
        # so filter in Python for correctness on small windows.
        rows = conn.execute(
            """
            SELECT created_at, status_error_code
            FROM signins
            WHERE tenant_id = ? AND user_principal_name = ?
            ORDER BY created_at DESC
            LIMIT 200
            """,
            (tenant_id, upn),
        ).fetchall()
        count = 0
        window_secs = window_minutes * 60
        for row in rows:
            code = row["status_error_code"]
            try:
                code_i = int(code) if code is not None else 0
            except (TypeError, ValueError):
                code_i = 0
            if code_i == 0:
                continue
            t = _parse_dt(row["created_at"])
            if t is None:
                continue
            if abs((current_time - t).total_seconds()) <= window_secs:
                count += 1
        return count

    row = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM signins
        WHERE tenant_id = ?
          AND user_principal_name = ?
          AND status_error_code IS NOT NULL
          AND status_error_code != 0
          AND created_at >= datetime('now', ?)
        """,
        (tenant_id, upn, f"-{int(window_minutes)} minutes"),
    ).fetchone()
    return int(row["c"] if row else 0)


def _impossible_travel(
    conn: sqlite3.Connection,
    tenant_id: str,
    signin: Dict[str, Any],
    window_minutes: int,
    country_field: str,
    time_field: str,
) -> Optional[Tuple[str, Dict[str, Any]]]:
    upn = signin.get("userPrincipalName")
    country = _norm_str(get_path(signin, country_field))
    created = get_path(signin, time_field)
    cur_time = _parse_dt(created)
    if not upn or not country or cur_time is None:
        return None

    # Previous sign-in excluding current graph id if present
    graph_id = signin.get("id")
    row = conn.execute(
        """
        SELECT created_at, location_country, graph_id
        FROM signins
        WHERE tenant_id = ? AND user_principal_name = ?
        ORDER BY created_at DESC
        LIMIT 5
        """,
        (tenant_id, upn),
    ).fetchall()

    prev_country = None
    prev_time = None
    for r in row:
        if graph_id and r["graph_id"] == graph_id:
            continue
        if not r["location_country"]:
            continue
        prev_country = _norm_str(r["location_country"])
        prev_time = _parse_dt(r["created_at"])
        break

    if not prev_country or prev_time is None:
        return None
    if prev_country.upper() == country.upper():
        return None
    if abs((cur_time - prev_time).total_seconds()) > window_minutes * 60:
        return None

    extra = {
        "from_country": prev_country,
        "window_minutes": window_minutes,
        "count": 1,
    }
    return prev_country, extra


def evaluate_signin(
    signin: Dict[str, Any],
    tenant_id: str,
    conn: sqlite3.Connection,
    rules_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """
    Evaluate all enabled rules against one Graph sign-in.

    Returns list of alert dicts:
      rule_id, name, severity, reason, group, tags, mitre, notify
    """
    from codexsiem.config import DETECTION_RULES_PATH

    path = rules_path or DETECTION_RULES_PATH
    try:
        rs = load_ruleset(path)
    except Exception:
        LOGGER.exception("Failed to load detection rules from %s; no YAML alerts", path)
        return []

    lists = rs.get("lists") or {}
    # Inject tenant_id for group_by / templates
    ctx = dict(signin)
    ctx["tenant_id"] = tenant_id

    hits: List[Dict[str, Any]] = []
    seen_ids = set()

    for rule in rs["rules"]:
        rid = rule["id"]
        if rid in seen_ids:
            continue

        matched = False
        extra: Dict[str, Any] = {}

        if rule.get("match"):
            matched = eval_condition(ctx, rule["match"], lists)

        corr = rule.get("correlate")
        if corr and isinstance(corr, dict):
            corr_type = (corr.get("type") or "").lower()
            window = int(corr.get("window_minutes") or 15)
            threshold = int(corr.get("threshold") or 1)

            if corr_type == "impossible_travel":
                fields = corr.get("fields") or {}
                country_f = fields.get("country") or "location.countryOrRegion"
                time_f = fields.get("time") or "createdDateTime"
                result = _impossible_travel(conn, tenant_id, signin, window, country_f, time_f)
                if result:
                    matched = True
                    _, extra = result
                    extra["window_minutes"] = window
            else:
                where = corr.get("where")
                if where and not eval_condition(ctx, where, lists):
                    matched = False
                else:
                    upn = _norm_str(signin.get("userPrincipalName"))
                    cur_time = _parse_dt(signin.get("createdDateTime"))
                    count = _failed_burst_count(conn, tenant_id, upn, window, cur_time)
                    if count >= threshold:
                        matched = True
                        extra = {"count": count, "window_minutes": window}

        if not matched:
            continue

        seen_ids.add(rid)
        reason = render_reason(rule["reason"], ctx, extra)
        hits.append(
            {
                "rule_id": rid,
                "name": rule["name"],
                "severity": rule["severity"],
                "reason": reason,
                "group": rule.get("group") or "",
                "tags": list(rule.get("tags") or []),
                "mitre": list(rule.get("mitre") or []),
                "notify": bool(rule.get("notify", True)),
            }
        )

    return hits


def rules_status(path: Optional[Path] = None) -> Dict[str, Any]:
    from codexsiem.config import DETECTION_RULES_PATH

    p = path or DETECTION_RULES_PATH
    try:
        rs = load_ruleset(p)
        return {
            "ok": True,
            "path": str(p),
            "version": rs.get("version"),
            "rule_count": len(rs.get("rules") or []),
            "lists": list((rs.get("lists") or {}).keys()),
        }
    except Exception as exc:
        return {"ok": False, "path": str(p), "error": str(exc)}
