"""Component 02 (Dynamic Planner & RAG) integration client.

Forwards the official X-IRE-Schema-Version: 1 payload produced by /parse
to the Component 02 /plan endpoint so the planner can construct the final
Kali command. The push is fail-open: any connectivity, auth or validation
failure is returned as structured metadata and never breaks /parse.
"""

from __future__ import annotations

import time
from typing import Optional

import httpx

REJECTED_LIKE = {"REJECTED", "AMBIGUOUS"}


class PlannerClient:
    def __init__(
        self,
        url: str,
        api_key: str,
        timeout_seconds: int = 300,
    ) -> None:
        self.base_url = url.rstrip("/")
        self.api_key = api_key
        self.timeout = httpx.Timeout(timeout_seconds)

    @staticmethod
    def should_push(
        intent: Optional[str],
        rejection_reason: Optional[str],
    ) -> bool:
        if not intent:
            return False
        if intent.upper() in REJECTED_LIKE:
            return False
        if rejection_reason:
            return False
        return True

    async def push(self, payload: dict) -> dict:
        started = time.perf_counter()
        body = dict(payload)
        body.setdefault("session_id", "anonymous-flow")

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/plan",
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": self.api_key,
                    },
                    json=body,
                )
            elapsed_ms = int((time.perf_counter() - started) * 1000)

            try:
                data = resp.json()
            except Exception:
                data = {"raw": resp.text[:2000]}

            if resp.status_code == 200:
                result = {"status": "success", "push_latency_ms": elapsed_ms}
                if isinstance(data, dict):
                    result.update(data)
                return result

            if resp.status_code == 400:
                return {
                    "status": "rejected",
                    "stage": "planner_validation",
                    "detail": data,
                    "push_latency_ms": elapsed_ms,
                }

            if resp.status_code == 401:
                return {
                    "status": "auth_failed",
                    "detail": data.get("detail", data),
                    "push_latency_ms": elapsed_ms,
                }

            return {
                "status": "error",
                "status_code": resp.status_code,
                "detail": data,
                "push_latency_ms": elapsed_ms,
            }

        except httpx.ConnectError as e:
            return {"status": "failed", "error": f"ConnectError: {e}"}
        except httpx.TimeoutException as e:
            return {"status": "failed", "error": f"Timeout: {e}"}
        except Exception as e:
            return {"status": "failed", "error": f"{type(e).__name__}: {e}"}