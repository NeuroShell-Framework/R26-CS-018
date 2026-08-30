import time
from datetime import datetime

class MetricsCollector:

    def __init__(self):
        self.metrics = []

    def start_timer(self) -> float:
        return time.time()

    def record(self, session_id: str, intent: str, tool: str,
               start_time: float, success: bool, safety_flags: list):

        latency_ms = int((time.time() - start_time) * 1000)

        entry = {
            "timestamp"   : datetime.utcnow().isoformat(),
            "session_id"  : session_id,
            "intent"      : intent,
            "tool"        : tool,
            "latency_ms"  : latency_ms,
            "success"     : success,
            "safety_flags": safety_flags,
        }

        self.metrics.append(entry)
        return latency_ms

    def get_summary(self) -> dict:
        if not self.metrics:
            return {"total": 0}

        total      = len(self.metrics)
        successful = sum(1 for m in self.metrics if m["success"])
        avg_latency = sum(m["latency_ms"] for m in self.metrics) // total

        return {
            "total"          : total,
            "successful"     : successful,
            "failed"         : total - successful,
            "avg_latency_ms" : avg_latency,
        }

    def reset(self):
        self.metrics.clear()


if __name__ == "__main__":
    mc = MetricsCollector()

    t = mc.start_timer()
    time.sleep(0.1)
    ms = mc.record("test-123", "NETWORK_SCAN", "nmap", t, True, [])
    print(f"Recorded: {ms}ms")

    t = mc.start_timer()
    time.sleep(0.2)
    ms = mc.record("test-123", "VULNERABILITY_AUDIT", "nikto", t, True, [])
    print(f"Recorded: {ms}ms")

    print(f"\nSummary: {mc.get_summary()}")