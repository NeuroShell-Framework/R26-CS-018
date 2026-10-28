"""Component 03 (AEERE executor) and Component 04 (AVAE analysis) clients.

Chains the /execute flow beyond C2: the planned Kali command is executed by
the AEERE service (Component 03), and the execution result is then fed to the
vulnerability analysis service (Component 04) for enrichment + ML scoring.

Both pushes are fail-open: connectivity, HTTP or schema failures are returned
as structured metadata and never break /execute.
"""

from __future__ import annotations

import time

import httpx


class ExecutorClient:
    """POSTs planned commands to Component 03 /execute and returns the
    normalized ExecutionResult (status: success | recovered | failed)."""

    def __init__(
        self,
        url: str,
        timeout_seconds: int = 300,
    ) -> None:
        self.base_url = url.rstrip("/")
        self.timeout = httpx.Timeout(timeout_seconds)

    async def push(self, payload: dict) -> dict:
        started = time.perf_counter()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/execute",
                    headers={"Content-Type": "application/json"},
                    json=payload,
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


class VulnerabilityClient:
    """POSTs an AEERE execution result to Component 04 /analyze and returns
    the AV analysis report (enrichment + exploitability + risk tiers)."""

    def __init__(
        self,
        url: str,
        timeout_seconds: int = 300,
    ) -> None:
        self.base_url = url.rstrip("/")
        self.timeout = httpx.Timeout(timeout_seconds)

    async def push(self, payload: dict) -> dict:
        started = time.perf_counter()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/analyze",
                    headers={"Content-Type": "application/json"},
                    json=payload,
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