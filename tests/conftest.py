import os

os.environ.setdefault("SIEM_ALLOW_INSECURE", "true")
os.environ.setdefault("SIEM_SESSION_SECRET", "test-secret-not-for-production")
