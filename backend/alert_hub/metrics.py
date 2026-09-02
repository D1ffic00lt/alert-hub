from prometheus_client import Counter, Gauge, Info

INGEST_TOTAL = Counter(
    "alert_hub_ingest_total",
    "Normalized events accepted by Alert Hub",
    ("source_kind", "status"),
)
INGEST_ERRORS = Counter(
    "alert_hub_ingest_errors_total",
    "Webhook requests rejected during ingest",
    ("source_kind", "reason"),
)
HEARTBEAT_EVALUATION_ERRORS = Counter(
    "alert_hub_heartbeat_evaluation_errors_total",
    "Heartbeat sources skipped because their replicated configuration is invalid",
    ("reason",),
)
INCIDENTS_OPEN = Gauge("alert_hub_incidents_open", "Current non-resolved incidents")
OUTBOX_PENDING = Gauge("alert_hub_outbox_pending", "Pending outbox records")
DELIVERY_TOTAL = Counter(
    "alert_hub_delivery_total", "Notification delivery attempts", ("channel_kind", "status")
)
DELIVERY_FAILURES = Counter(
    "alert_hub_delivery_failures_total", "Failed notification deliveries", ("channel_kind",)
)
SYNC_EVENTS = Counter(
    "alert_hub_sync_events_total", "Cluster events sent or applied", ("direction", "result")
)
SYNC_LAG = Gauge(
    "alert_hub_sync_lag_seconds", "Oldest unapplied cluster event age", ("peer_node_id",)
)
CLOCK_SKEW_SUSPECTED = Gauge(
    "alert_hub_clock_skew_suspected",
    "Whether a peer event timestamp differs from local time beyond the configured threshold",
    ("peer_node_id",),
)
PEER_UP = Gauge(
    "alert_hub_peer_up", "Whether a configured cluster peer is reachable", ("peer_node_id",)
)
DB_ERRORS = Counter("alert_hub_db_errors_total", "Database operation failures", ("operation",))
BUILD_INFO = Info("alert_hub_build", "Alert Hub build information")
