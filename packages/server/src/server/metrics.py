# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

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
# #685 (owner ruling 2026-10-20): the series is declared and no longer incremented — the
# maintenance-loop pass that fed it was removed when ExecutorCertRevocation became exempt
# from time-based purge. It stays shipped on purpose: an operator who sees this counter
# above zero after a revert is looking at the exact hazard #685 closed, and a family that
# vanishes from the exposition is a scrape-side change nobody ruled. See
# `server/maintenance.py::run_maintenance` for the exemption text.
CRL_TRUNCATED_TOTAL = Counter(
    "venya_crl_truncated_total",
    "CRL responses served while revocation history exceeds the entry ceiling (refs #337)",
    [],
)

# #603 AC1: the alerting surface for a bounded revocation read that could not answer inside its
# lock deadline. CUMULATIVE BY DESIGN — the #651 defect shape was a per-emit WARNING with no
# counter, so a losing component could never later state how much it lost. The log line is
# latched (once per process); this counter is never latched, so the count survives the latch.
# #657: the SAME series now also carries the snapshot-stale arm — the refusal a starved pool or a
# dead publisher actually produces — under its own ``site`` value
# (``revocation_snapshot.POLL_REFUSAL_SITE`` = ``poll/revocation-list``). The name and the label
# set are unchanged; the help text names both arms so a reader of the scrape is not told a lie.
# Adding a second series here would be wrong in the other direction: an alert pointed at a name
# that does not exist is the defect this plane keeps re-fixing.
REVOCATION_READ_REFUSALS_TOTAL = Counter(
    "venya_revocation_read_refusals_total",
    "Revocation-plane reads refused with no answer: lock deadline (#603 AC1) or stale/missing "
    "snapshot (#657); 'site' names which path refused",
    ["site"],
)

# #654: the SLOW-SCAN refusal, on its own cumulative counter. Deliberately a NEW family rather than
# a new label value on the #603 series above — a label added to an existing series silently
# re-splits every operator query and dashboard built on it — and deliberately not folded into it
# either, because #603 AC1's first criterion is that a lock wait and a read that merely ran long
# are two different failures an operator chases two different ways. Same site vocabulary.
REVOCATION_READ_SCAN_REFUSALS_TOTAL = Counter(
    "venya_revocation_read_scan_refusals_total",
    "Revocation-plane reads cancelled by their own statement deadline (refs #654)",
    ["site"],
)

# #654's visibility half. A read that runs slowly and then SUCCEEDS raises nothing, so no counter can
# ever see it — and `venya_request_duration_seconds` above cannot express it either, because its top
# bucket is 10.0 s while the bound that actually governed these reads was the 300 s session
# statement_timeout: a 12 s read and a 300 s read were the same `+Inf` observation. These buckets
# reach 300 s so the histogram is a measurement of the quantity the row is about.
REVOCATION_READ_DURATION_SECONDS = Histogram(
    "venya_revocation_read_duration_seconds",
    "Time spent inside one bounded revocation read, by site (refs #654)",
    ["site"],
    buckets=(0.025, 0.05, 0.1, 0.3, 1.0, 2.5, 5.0, 10.0, 30.0, 300.0),
)

# A revocation read that could not determine its dialect ran with NO bound at all. This is its own
# family, not a label on the #603 refusals series: "the seam installed nothing" and "the seam refused"
# are two different facts an operator chases two different ways, and #654's own reasoning binds here —
# a label added to an existing series silently re-splits every operator query and dashboard built on
# it. A clean non-PG install never increments it: `sqlite` answers the question honestly, so only the
# unanswerable state counts. Found on leg 478 (s266) and filed as #704 from the leg-471 enumeration.
REVOCATION_READ_UNBOUNDED_TOTAL = Counter(
    "venya_revocation_read_unbounded_total",
    "Revocation-plane reads that ran with NO deadline installed because the session could not report "
    "its dialect (the bind raised); 'site' names which path. Not a refusal — nothing was refused "
    "(found leg 478, s266)",
    ["site"],
)

# --- Core metrics ---

CORE_OPERATIONS_TOTAL = Counter(
    "venya_core_operations_total",
    "Total core cryptographic operations",
    ["operation", "result"],
)
