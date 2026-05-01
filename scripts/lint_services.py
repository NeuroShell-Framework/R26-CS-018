#!/usr/bin/env python3
"""
Script to lint and fix linting issues in all NeuroShell services.
This script runs ruff (linting and fixing) and black (formatting) on each service.
"""

import subprocess
import sys
from pathlib import Path

# List of service directories relative to the project root
SERVICES = [
    "apps/services/adaptive-execution-error-recovery",
    "apps/services/ai-vulnerability-analysis",
    "apps/services/dynamic-planner-rag",
    "apps/services/intent-recognition",
]

def run_command(command: list[str], cwd: Path) -> bool:
    """Run a command in the specified directory and return success status."""
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True
        )
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running {' '.join(command)} in {cwd}:")
        if e.stdout:
            print(e.stdout)
        if e.stderr:
            print(e.stderr)
        return False

def lint_service(service_path: Path) -> bool:
    """Lint and fix a single service."""
    print(f"\n{'='*50}")
    print(f"Linting service: {service_path}")
    print('='*50)

    success = True

    # Run ruff check
    print(f"\nRunning ruff check on {service_path}...")
    if not run_command(["ruff", "check", "--show-fixes", "."], service_path):
        success = False

    # Run ruff fix
    print(f"\nRunning ruff fix on {service_path}...")
    if not run_command(["ruff", "check", "--fix", "."], service_path):
        success = False

    # Run black
    print(f"\nRunning black on {service_path}...")
    if not run_command(["black", "."], service_path):
        success = False

    return success

def main():
    """Main function to lint all services."""
    project_root = Path(__file__).parent.parent

    print("NeuroShell Services Linting Script")
    print(f"Project root: {project_root}")
    print(f"Services to lint: {len(SERVICES)}")

    all_success = True

    for service in SERVICES:
        service_path = project_root / service
        if not service_path.exists():
            print(f"Warning: Service directory {service_path} does not exist")
            continue

        if not lint_service(service_path):
            all_success = False

    print(f"\n{'='*50}")
    if all_success:
        print("All services linted successfully!")
        return 0
    else:
        print("Some services had linting issues. Please review the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())