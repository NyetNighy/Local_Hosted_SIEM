"""Backward-compatible thin wrapper for CodexSIEM startup."""

from __future__ import annotations

import argparse
import importlib
import py_compile
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _compile_required_targets() -> int:
    """Check required targets compile correctly."""
    targets = [
        ROOT / "scripts" / "verify_runtime.py",
        ROOT / "application.py",
        ROOT / "main.py",
    ]
    for target in targets:
        try:
            py_compile.compile(str(target), doraise=True)
        except py_compile.PyCompileError as exc:
            print(f"Preflight compile check failed for {target}: {exc.msg}", file=sys.stderr)
            print("Remediation: sync your checkout and rerun startup.", file=sys.stderr)
            return 1
    return 0


def _minimal_import_preflight() -> int:
    """Check that core modules can be imported."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    for module in ("application", "main"):
        try:
            imported = importlib.import_module(module)
            print(f"Imported {module} from: {getattr(imported, '__file__', '<unknown>')}")
        except Exception as exc:  # noqa: BLE001
            print(f"Preflight import check failed for {module}: {exc}", file=sys.stderr)
            return 1
    print("Minimal preflight checks passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CodexSIEM with preflight runtime checks.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default="8000")
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    # Run preflight checks
    compile_status = _compile_required_targets()
    if compile_status != 0:
        return compile_status

    # Run runtime verification
    verify_cmd = [sys.executable, str(ROOT / "scripts" / "verify_runtime.py")]
    verify = subprocess.run(verify_cmd, cwd=ROOT)
    if verify.returncode != 0:
        print("Preflight failed. Fix the issues above before starting uvicorn.", file=sys.stderr)
        return verify.returncode

    # Build uvicorn command
    uvicorn_cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "main:app",
        "--host",
        args.host,
        "--port",
        str(args.port),
    ]

    if args.reload:
        uvicorn_cmd.append("--reload")

    try:
        return subprocess.call(uvicorn_cmd, cwd=ROOT)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
