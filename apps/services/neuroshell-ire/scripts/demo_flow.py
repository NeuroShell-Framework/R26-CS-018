"""Automated C1 -> C2 demo flow orchestrator.

Fires Component 01 (/parse), feeds its version1 contract directly into
Component 02 (/plan), and prints both labeled bodies so the panel can see
the handoff without copying/pasting between Swagger UIs.

Usage:
    python demo_flow.py [--command "..."]

Both services must be running:
    C1: http://localhost:8001  (NeuroShell IRE)
    C2: http://localhost:8002  (Dynamic Planner)
"""

from __future__ import annotations

import argparse
import json
import os

import httpx

C1_URL = os.getenv("C1_URL", "http://localhost:8001")
C2_URL = os.getenv("C2_URL", "http://localhost:8002")
C1_KEY = os.getenv("C1_API_KEY", "dev_insecure_key")
C2_KEY = os.getenv(
    "C2_API_KEY",
    "neuroshell-c2-secret-key",
)

DEFAULT_COMMAND = (
    "run a brute force attack on 192.168.10.25 using hydra"
)

TIMEOUT = 600.0


def _dump(label: str, body: dict) -> None:
    print(f"\n{'=' * 62}\n{label}\n{'=' * 62}")
    print(json.dumps(body, indent=2, ensure_ascii=False))


def run(command: str, session_id: str, role: str = "admin") -> int:
    print(f"-> command      : {command}")
    print(f"-> session      : {session_id}")
    print(f"-> role         : {role}\n")

    with httpx.Client(timeout=TIMEOUT) as client:
        _dump(
            "USER INPUT",
            {
                "command": command,
                "session_id": session_id,
                "role": role,
            },
        )

        # ── Component 01: intent recognition ──────────────────────────────
        c1 = client.post(
            f"{C1_URL}/parse",
            headers={"X-API-Key": C1_KEY},
            json={
                "command": command,
                "session_id": session_id,
                "role": role,
            },
        )
        c1.raise_for_status()
        c1_body = c1.json()

        version1 = c1_body.get("version1") or {}
        version2 = c1_body.get("version2") or {}

        _dump("COMPONENT 01 OUTPUT — Schema-Version 1 (fed to C2)", version1)
        _dump("COMPONENT 01 OUTPUT — Schema-Version 2 (extended)", version2)

        if (version2 or {}).get("status") != "success":
            print("\nC1 did not produce a success contract; stopping.")
            return 1

        if "intent_contract" not in version1:
            print("\nversion1 has no intent_contract; stopping.")
            return 1

        # ── Component 02: command synthesis from C1's v1 body ─────────────
        print(f"\n-> forwarding version1 to {C2_URL}/plan ...")
        plan_payload = dict(version1)

        c2 = client.post(
            f"{C2_URL}/plan",
            headers={
                "Content-Type": "application/json",
                "x-api-key": C2_KEY,
            },
            json=plan_payload,
        )
        c2_body = c2.json()

        _dump(
            "COMPONENT 02 OUTPUT — constructed Kali command "
            f"(HTTP {c2.status_code})",
            c2_body,
        )

        if c2.status_code == 200:
            cmd = c2_body.get("command")
            print(
                "\nFLOW OK: C1 intent -> C2 command  "
                f"[ {cmd} ]"
            )
            return 0

        print("\nC2 did not accept the contract (see body above).")
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Automated C1 -> C2 demo flow"
    )
    parser.add_argument(
        "--command",
        default=DEFAULT_COMMAND,
        help="command to analyze through C1 -> C2",
    )
    parser.add_argument(
        "--session-id",
        default="web-01",
        help="session id (defaults to web-01)",
    )
    parser.add_argument(
        "--role",
        default="admin",
        help="RBAC role (defaults to admin)",
    )
    args = parser.parse_args()

    session_id = args.session_id or f"demo-{os.getpid()}"
    return run(args.command, session_id, args.role)


if __name__ == "__main__":
    raise SystemExit(main())