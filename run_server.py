#!/usr/bin/env python3
"""Start CodexSIEM with uvicorn.

Usage:
  export SIEM_SESSION_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
  python run_server.py --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import argparse
import os
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Start CodexSIEM")
    parser.add_argument("--host", default=os.getenv("SIEM_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SIEM_PORT", "8000")))
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        print("uvicorn is required. Install with: pip install -r requirements.txt", file=sys.stderr)
        return 1

    uvicorn.run("application:app", host=args.host, port=args.port, reload=args.reload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
