import docker
import time
import os
from dotenv import load_dotenv
from src.schemas.models import RawExecutionResult

load_dotenv()

KALI_IMAGE = os.getenv('KALI_IMAGE', 'kalilinux/kali-rolling')
MEM_LIMIT  = os.getenv('CONTAINER_MEM_LIMIT', '512m')
CPU_QUOTA  = int(os.getenv('CONTAINER_CPU_QUOTA', '50000'))
EXEC_TIMEOUT = int(os.getenv('CONTAINER_EXEC_TIMEOUT', '60'))


class CommandRunner:

    def __init__(self):
        self._client = None

    @property
    def client(self):
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def execute(self, command: str, timeout: int = None) -> RawExecutionResult:
        timeout = timeout or EXEC_TIMEOUT
        container = None
        try:
            container = self.client.containers.run(
                image=KALI_IMAGE,
                command=['bash', '-c', command],
                detach=True,
                mem_limit=MEM_LIMIT,
                cpu_quota=CPU_QUOTA,
                network_mode='bridge',
                privileged=True,
                environment=["DEBIAN_FRONTEND=noninteractive"],
            )
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
                command=command,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=timed_out
            )
        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    def check_docker_available(self) -> bool:
        try:
            self.client.ping()
            return True
        except Exception:
            return False
