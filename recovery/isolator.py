"""
checks threat_scores for any ip that has crossed the critical
threshold and hasn't been marked as blocked yet. marks it blocked
and logs the isolation action.

note: this records the decision and a full audit trail in the
database. actually dropping their packets at the network layer
(iptables/nftables) is a natural next step but is intentionally
out of scope here — modifying the VM's live firewall rules from
inside a container is a bigger, riskier change than this project
needs, and the decision-and-logging layer is what we demonstrate.
"""

import logging
import os

log = logging.getLogger("nullbait.isolator")

CRITICAL_THREAT_SCORE = int(os.getenv("CRITICAL_THREAT_SCORE", 75))


async def check_for_isolation(conn):
    rows = await conn.fetch(
        """
        SELECT attacker_ip, score, threat_level
        FROM threat_scores
        WHERE score >= $1 AND is_blocked = FALSE
        """,
        CRITICAL_THREAT_SCORE,
    )

    for row in rows:
        ip = row["attacker_ip"]

        await conn.execute(
            """
            UPDATE threat_scores
            SET is_blocked = TRUE, blocked_at = NOW()
            WHERE attacker_ip = $1
            """,
            ip,
        )

        await conn.execute(
            """
            INSERT INTO recovery_history (service, action, trigger_reason, success, notes)
            VALUES ($1, $2, $3, $4, $5)
            """,
            "isolator", "isolate", f"threat score {row['score']} crossed critical threshold",
            True, f"ip {ip} marked as blocked in threat_scores",
        )

        await conn.execute(
            """
            INSERT INTO alerts (severity, title, message, attacker_ip)
            VALUES ($1, $2, $3, $4)
            """,
            "critical", f"IP {ip} isolated",
            f"Threat score reached {row['score']} ({row['threat_level']}) — marked as blocked",
            ip,
        )

        log.warning("isolated ip %s — threat score %d", ip, row["score"])
