"""Unit tests for YAML detection rules engine."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codexsiem.rules_engine import eval_condition, evaluate_signin, load_ruleset, render_reason


@pytest.fixture
def rules_path() -> Path:
    root = Path(__file__).resolve().parents[1]
    path = root / "rules" / "detections.yaml"
    if not path.is_file():
        pytest.skip("rules/detections.yaml not present")
    return path


@pytest.fixture
def memory_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE signins (
            tenant_id TEXT,
            graph_id TEXT,
            created_at TEXT,
            user_principal_name TEXT,
            status_error_code INTEGER,
            location_country TEXT
        );
        """
    )
    return conn


def test_load_default_rules(rules_path: Path) -> None:
    rs = load_ruleset(rules_path, force=True)
    assert rs["rule_count"] if False else len(rs["rules"]) >= 5
    ids = {r["id"] for r in rs["rules"]}
    assert "auth.failed_signin" in ids
    assert "geo.impossible_travel" in ids


def test_failed_signin_match(rules_path: Path, memory_conn: sqlite3.Connection) -> None:
    signin = {
        "id": "g1",
        "userPrincipalName": "user@contoso.com",
        "createdDateTime": "2026-01-01T12:00:00Z",
        "status": {"errorCode": 50126},
        "location": {"countryOrRegion": "US"},
    }
    hits = evaluate_signin(signin, "tenant-a", memory_conn, rules_path=rules_path)
    ids = {h["rule_id"] for h in hits}
    assert "auth.failed_signin" in ids
    assert any("50126" in h["reason"] for h in hits)


def test_success_signin_no_failure(rules_path: Path, memory_conn: sqlite3.Connection) -> None:
    signin = {
        "id": "g2",
        "userPrincipalName": "user@contoso.com",
        "createdDateTime": "2026-01-01T12:00:00Z",
        "status": {"errorCode": 0},
        "location": {"countryOrRegion": "US"},
    }
    hits = evaluate_signin(signin, "tenant-a", memory_conn, rules_path=rules_path)
    ids = {h["rule_id"] for h in hits}
    assert "auth.failed_signin" not in ids


def test_high_risk_country(rules_path: Path, memory_conn: sqlite3.Connection) -> None:
    signin = {
        "id": "g3",
        "userPrincipalName": "user@contoso.com",
        "createdDateTime": "2026-01-01T12:00:00Z",
        "status": {"errorCode": 0},
        "location": {"countryOrRegion": "RU"},
    }
    hits = evaluate_signin(signin, "tenant-a", memory_conn, rules_path=rules_path)
    assert any(h["rule_id"] == "geo.high_risk_country" for h in hits)


def test_legacy_client(rules_path: Path, memory_conn: sqlite3.Connection) -> None:
    signin = {
        "id": "g4",
        "userPrincipalName": "user@contoso.com",
        "createdDateTime": "2026-01-01T12:00:00Z",
        "status": {"errorCode": 0},
        "clientAppUsed": "IMAP4",
        "location": {},
    }
    hits = evaluate_signin(signin, "tenant-a", memory_conn, rules_path=rules_path)
    assert any(h["rule_id"] == "auth.legacy_client" for h in hits)


def test_render_reason_template() -> None:
    text = render_reason(
        "Failed ({{ status.errorCode }}) count={{ correlate.count }}",
        {"status": {"errorCode": 50126}},
        {"count": 5},
    )
    assert "50126" in text
    assert "5" in text


def test_eval_condition_in_list() -> None:
    lists = {"high_risk_countries": ["RU", "KP"]}
    ok = eval_condition(
        {"location": {"countryOrRegion": "ru"}},
        {"field": "location.countryOrRegion", "op": "in_list", "list": "high_risk_countries"},
        lists,
    )
    assert ok is True
