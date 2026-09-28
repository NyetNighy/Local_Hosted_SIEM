"""Reconstruct codexsiem/_routes_src.py from base64 chunk files."""
from __future__ import annotations

import base64
from pathlib import Path

_DIR = Path(__file__).resolve().parent
_OUT = _DIR / "_routes_src.py"


def ensure_routes_src() -> Path:
    if _OUT.exists() and _OUT.stat().st_size > 1000:
        return _OUT
    parts = sorted(_DIR.glob("_routes_b64_*.txt"))
    if not parts:
        raise FileNotFoundError("Missing _routes_b64_*.txt chunks and _routes_src.py")
    b64 = "".join(p.read_text(encoding="utf-8") for p in parts)
    src = base64.b64decode(b64.encode("ascii")).decode("utf-8")
    _OUT.write_text(src, encoding="utf-8")
    return _OUT


if __name__ == "__main__":
    path = ensure_routes_src()
    print(f"Wrote {path} ({path.stat().st_size} bytes)")
