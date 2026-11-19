#!/usr/bin/env python
"""Build Sphinx documentation for VaultConfig."""

import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    docs_dir = Path(__file__).resolve().parent
    build_dir = docs_dir / "_build"
    source_dir = docs_dir

    target = sys.argv[1] if len(sys.argv) > 1 else "html"
    if target == "clean":
        if build_dir.exists():
            print(f"Cleaning {build_dir}...")
            shutil.rmtree(build_dir)
        return 0

    if target == "help":
        print(__doc__)
        print("Targets: html, dirhtml, latex, text, man, changes, linkcheck, doctest, all")
        return 0

    valid_targets = {
        "html",
        "dirhtml",
        "latex",
        "text",
        "man",
        "changes",
        "linkcheck",
        "doctest",
        "all",
    }
    if target not in valid_targets:
        print(f"Unknown target: {target}")
        print("Use 'help' target for help")
        return 1

    sphinx = [sys.executable, "-m", "sphinx", "-n", "-W", "--keep-going"]
    builders = ["html", "dirhtml", "latex"] if target == "all" else [target]
    for builder in builders:
        output_dir = build_dir / builder
        command = [*sphinx, "-b", builder, str(source_dir), str(output_dir)]
        print(f"Building {builder} documentation...")
        subprocess.run(command, check=True)

    if target == "all":
        print(f"Build finished. Documentation is in {build_dir}")
    else:
        print(f"Build finished. Documentation is in {build_dir / target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
