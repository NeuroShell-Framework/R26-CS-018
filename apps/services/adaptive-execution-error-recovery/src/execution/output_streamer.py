"""
Output Streamer — captures Docker container output in real-time chunks.
"""

import docker
from src.schemas.models import RawExecutionResult


class OutputStreamer:
    """Streams stdout/stderr from a running Docker container."""

    def __init__(self):
        try:
            self.client = docker.from_env()
        except Exception:
            self.client = None

    def stream_output(self, container_id: str, follow: bool = True):
        """Yield log lines from a running container."""
        if not self.client:
            return
        try:
            container = self.client.containers.get(container_id)
            for line in container.logs(stream=True, follow=follow):
                yield line.decode('utf-8', 'replace')
        except Exception:
            return

    def collect_output(self, container_id: str, timeout: int = 60) -> RawExecutionResult:
        """Wait for a container to finish and collect all output."""
        if not self.client:
            return RawExecutionResult(
                command='', stdout='', stderr='Error: Docker unavailable',
                exit_code=1, timed_out=False,
            )
        try:
            container = self.client.containers.get(container_id)
            try:
                result = container.wait(timeout=timeout)
                exit_code = result.get('StatusCode', 1)
                timed_out = False
            except Exception:
                container.stop(timeout=2)
                exit_code = 124
                timed_out = True

            stdout = container.logs(stdout=True, stderr=False).decode('utf-8', 'replace')
            stderr = container.logs(stdout=False, stderr=True).decode('utf-8', 'replace')

            return RawExecutionResult(
                command='', stdout=stdout, stderr=stderr,
                exit_code=exit_code, timed_out=timed_out,
            )
        except Exception as e:
            return RawExecutionResult(
                command='', stdout='', stderr=str(e),
                exit_code=1, timed_out=False,
            )
