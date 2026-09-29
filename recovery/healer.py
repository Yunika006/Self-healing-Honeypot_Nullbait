"""
handles the actual recovery actions — restarting containers,
and recording what happened so there's a permanent audit trail
in recovery_history. this is what lets you show an examiner
"here's proof the system healed itself" with a real timestamped log.
"""

import logging
import time

import docker

log = logging.getLogger("nullbait.healer")


def attempt_restart(client: docker.DockerClient, container_name: str) -> tuple[bool, int, str]:
    """
    tries to restart the given container.
    returns (success: bool, duration_ms: int, notes: str)
    """
    start = time.time()

    try:
        container = client.containers.get(container_name)
        container.restart(timeout=10)

        duration_ms = int((time.time() - start) * 1000)
        return True, duration_ms, f"restarted successfully in {duration_ms}ms"

    except docker.errors.NotFound:
        duration_ms = int((time.time() - start) * 1000)
        return False, duration_ms, "container not found, cannot restart — it may need to be recreated"

    except Exception as e:
        duration_ms = int((time.time() - start) * 1000)
        return False, duration_ms, f"restart attempt raised an error: {e}"


async def record_recovery(
    conn, service: str, action: str, trigger_reason: str,
    success: bool, duration_ms: int, notes: str,
):
    await conn.execute(
        """
        INSERT INTO recovery_history
            (service, action, trigger_reason, success, duration_ms, notes)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        service, action, trigger_reason, success, duration_ms, notes,
    )
