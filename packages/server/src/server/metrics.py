"""Prometheus metrics registry for the Venya server.

Singleton registry with tuned buckets and cardinality discipline.
No high-cardinality labels (executor_id, user_id, ip, session_id).
All metrics are in-process counters/gauges/histograms — no external calls.
"""

from prometheus_client import Counter, Gauge, Histogram

# --- Request metrics ---

REQUEST_DURATION = Histogram(
    "venya_request_duration_seconds",
    "HTTP request duration in seconds",
    ["endpoint", "method", "status_code"],
    buckets=(
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1.0,
        2.5,
        5.0,
        10.0,
    ),
)

REQUESTS_TOTAL = Counter(
    "venya_requests_total",
    "Total HTTP requests",
    ["endpoint", "method", "status_code"],
)

# --- Executor metrics ---

EXECUTOR_REGISTERED = Counter(
    "venya_executor_registered_total",
    "Total executor registrations",
    ["result"],
)

EXECUTOR_HEARTBEAT_TOTAL = Counter(
    "venya_executor_heartbeat_total",
    "Total executor heartbeats received",
    [],
)

EXECUTOR_ACTIVE_GAUGE = Gauge(
    "venya_executor_active_total",
    "Current number of active executors",
    [],
)

# --- Token metrics ---

TOKEN_CREATED = Counter(
    "venya_token_created_total",
    "Total enrollment tokens created",
    ["type"],
)

TOKEN_CONSUMED = Counter(
    "venya_token_consumed_total",
    "Total enrollment token consumption attempts",
    ["result"],
)

TOKEN_REVOKED = Counter(
    "venya_token_revoked_total",
    "Total tokens revoked by admin",
    ["reason"],
)

# --- Auth metrics ---

AUTH_LOGIN_TOTAL = Counter(
    "venya_auth_login_total",
    "Total authentication login attempts",
    ["mode", "result"],
)

AUTH_REFRESH_TOTAL = Counter(
    "venya_auth_refresh_total",
    "Total token refresh attempts",
    ["result"],
)

# --- Rate limiting ---

RATE_LIMIT_HIT_TOTAL = Counter(
    "venya_rate_limit_hit_total",
    "Total rate limit hits",
    ["limit_type"],
)

# --- CA metrics ---

CA_SIGNED_TOTAL = Counter(
    "venya_ca_signed_total",
    "Total certificates signed by CA",
    ["cert_type"],
)

CA_SIGNED_DURATION = Histogram(
    "venya_ca_signed_duration_seconds",
    "Time spent signing certificates",
    ["cert_type"],
    buckets=(
        0.001,
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1.0,
    ),
)

CA_CRL_GENERATED_TOTAL = Counter(
    "venya_ca_crl_generated_total",
    "Total CRL generations",
    [],
)

CA_REVOCATIONS_PURGED_TOTAL = Counter(
    "venya_ca_revocations_purged_total",
    "Total expired revocation records purged",
    [],
)

# --- Core metrics ---

CORE_OPERATIONS_TOTAL = Counter(
    "venya_core_operations_total",
    "Total core cryptographic operations",
    ["operation", "result"],
)
