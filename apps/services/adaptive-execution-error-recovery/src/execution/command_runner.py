import docker
import time
import os
from dotenv import load_dotenv
from src.schemas.models import RawExecutionResult

load_dotenv()

KALI_IMAGE = os.getenv('KALI_IMAGE', 'kalilinux/kali-rolling')
MEM_LIMIT  = os.getenv('CONTAINER_MEM_LIMIT', '512m')
CPU_QUOTA  = int(os.getenv('CONTAINER_CPU_QUOTA', '50000'))

# Lab target network. C3 executions run inside throwaway containers; on the
# default bridge they cannot reach the 192.168.1.x lab range that the planner's
# contracts target, so scans report "host seems down" / time out.
LAB_NETWORK      = os.getenv('LAB_NETWORK', 'neuroshell-lab')
LAB_SUBNET       = os.getenv('LAB_SUBNET', '192.168.1.0/24')
LAB_GATEWAY      = os.getenv('LAB_GATEWAY', '192.168.1.1')
LAB_TARGET_IMAGE = os.getenv('LAB_TARGET_IMAGE', 'neuroshell-target')
LAB_TARGET_NAME  = os.getenv('LAB_TARGET_NAME', 'neuroshell-lab-target')
LAB_TARGET_IP    = os.getenv('LAB_TARGET_IP', '192.168.1.10')


class CommandRunner:

    def __init__(self):
        self._client = None
        self._lab_network = None

    @property
    def client(self):
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def _ensure_target(self):
        container = None
        try:
            container = self.client.containers.get(LAB_TARGET_NAME)
            on_lab = LAB_NETWORK in container.attrs.get('NetworkSettings', {}).get('Networks', {})
            if container.status != 'running' or not on_lab:
                container.remove(force=True)
                container = None
        except docker.errors.NotFound:
            container = None
        if container is not None:
            return
        self.client.containers.run(
            image=LAB_TARGET_IMAGE,
            command=['sleep', 'infinity'],
            name=LAB_TARGET_NAME,
            detach=True,
            network=LAB_NETWORK,
            ipv4_address=LAB_TARGET_IP,
            labels={'neuroshell.role': 'lab-target'},
        )

    def _ensure_lab_network(self):
        if self._lab_network:
            return self._lab_network
        try:
            try:
                self.client.networks.get(LAB_NETWORK)
            except docker.errors.NotFound:
                self.client.networks.create(
                    LAB_NETWORK,
                    driver='bridge',
                    ipam=docker.types.IPAMConfig(
                        pool_configs=[docker.types.IPAMPool(subnet=LAB_SUBNET, gateway=LAB_GATEWAY)]
                    ),
                    labels={'neuroshell.role': 'lab'},
                )
            self._ensure_target()
            self._lab_network = LAB_NETWORK
            return self._lab_network
        except Exception:
            return None

    def execute(self, command: str, timeout: int = 60) -> RawExecutionResult:
        container = None
        try:
            run_kwargs = dict(
                image=KALI_IMAGE,
                command=['bash', '-c', command],
                detach=True,
                mem_limit=MEM_LIMIT,
                cpu_quota=CPU_QUOTA,
                privileged=True,
                environment=["DEBIAN_FRONTEND=noninteractive"],
            )
            lab_network = self._ensure_lab_network()
            if lab_network:
                run_kwargs['network'] = lab_network
            else:
                run_kwargs['network_mode'] = 'bridge'

            container = self.client.containers.run(**run_kwargs)
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
