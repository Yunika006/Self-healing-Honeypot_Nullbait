"""
custom prometheus metrics for nullbait. these get scraped by
prometheus every 15s and visualized in grafana.
"""

from prometheus_client import Counter, Gauge, Histogram

# counts every attack event, broken down by service and event type —
# this is what lets grafana draw an "attacks per minute" graph
attack_events_total = Counter(
    "nullbait_attack_events_total",
    "Total number of attack events received",
    ["service", "event_type"],
)

# counts login attempts specifically, broken down by service —
# useful for a dedicated "brute force activity" panel
login_attempts_total = Counter(
    "nullbait_login_attempts_total",
    "Total number of login attempts captured",
    ["service"],
)

# how many dashboard clients are currently connected via websocket
active_websocket_connections = Gauge(
    "nullbait_active_websocket_connections",
    "Number of currently connected dashboard websocket clients",
)

# how many unique attacker ips we've ever seen — a gauge because
# it can be recalculated, not just incremented
unique_attackers_gauge = Gauge(
    "nullbait_unique_attackers",
    "Total number of unique attacker IPs seen",
)

# how many ips are currently flagged critical
critical_threats_gauge = Gauge(
    "nullbait_critical_threats",
    "Number of attacker IPs currently at critical threat level",
)

# request latency for our own REST API — standard FastAPI observability
request_latency_seconds = Histogram(
    "nullbait_request_latency_seconds",
    "Latency of backend API requests",
    ["endpoint"],
)
