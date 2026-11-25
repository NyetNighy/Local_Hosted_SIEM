# repair_entrypoints.py
#
# Helper script for CodexSIEM / enterprise-launcher to repair entrypoint
# files when git operations (merge, rebase, checkout) leave them damaged.

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

TEMPLATES = {
    "app.py": "app.py.template",
    "application.py": "application.py.template",
}


def _load_template(template_name: str) -> str:
    """Load a template from the template directory."""
    template_path = ROOT / "templates" / template_name
    return template_path.read_text(encoding="utf-8")


def _restore_application_from_git() -> int:
    """Restore application.py from git checkout."""
    app_py = ROOT / "application.py"
    if not app_py.exists():
        print("application.py not found in the repository.")
        return 0

    # Run git checkout for application.py
    import subprocess
    result = subprocess.run(
        ["git", "checkout", "--", "application.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print("Restored application.py from git")
        return 0
    else:
        print(f"Failed to checkout application.py: {result.stderr}")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Repair CodexSIEM entrypoint files.")
    parser.add_argument(
        "--include-application",
        action="store_true",
        help="Also restore application.py from git checkout.",
    )
    args = parser.parse_args()

    for relative_path, content in TEMPLATES.items():
        path = ROOT / relative_path
        path.write_text(content, encoding="utf-8")
        print(f"Repaired {relative_path}")

    if args.include_application:
        return _restore_application_from_git()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
