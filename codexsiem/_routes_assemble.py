"""Assemble full route source from part files."""
from __future__ import annotations

from pathlib import Path

_DIR = Path(__file__).resolve().parent
_OUT = _DIR / "_routes_src.py"
_PARTS = ("_routes_part1.py", "_routes_part2.py", "_routes_part3.py")


def ensure_routes_src() -> Path:
    """Always rebuild from parts so route updates are picked up."""
    chunks = []
    for name in _PARTS:
        p = _DIR / name
        if not p.exists():
            raise FileNotFoundError(f"Missing route part: {p}")
        chunks.append(p.read_text(encoding="utf-8"))
    _OUT.write_text("".join(chunks), encoding="utf-8")
    return _OUT


if __name__ == "__main__":
    path = ensure_routes_src()
    print(f"Wrote {path} ({path.stat().st_size} bytes)")
