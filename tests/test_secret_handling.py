from secret_utils import ENV_REF_PLACEHOLDER, resolve_client_secret


def test_resolve_from_env_ref(monkeypatch):
    monkeypatch.setenv("TENANT_X_SECRET", "super-secret")
    row = {"client_secret_ref": "TENANT_X_SECRET", "client_secret": ""}
    assert resolve_client_secret(row) == "super-secret"


def test_resolve_from_raw_secret():
    row = {"client_secret_ref": "", "client_secret": "inline-secret"}
    assert resolve_client_secret(row) == "inline-secret"


def test_placeholder_not_used_as_secret():
    row = {"client_secret_ref": "", "client_secret": ENV_REF_PLACEHOLDER}
    assert resolve_client_secret(row) is None
