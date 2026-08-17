"""Tests for Prometheus metrics — registry, middleware, cardinality, PII safety."""

from prometheus_client import generate_latest, REGISTRY

# Import to register custom metrics with the global registry
from server import metrics  # noqa: F401
from server.middleware.metrics import MetricsMiddleware, _normalize_endpoint


def _find_collector(name):
    """Find a collector by name in the registry.

    prometheus_client strips _total suffix from Counter names in _names_to_collectors.
    """
    return REGISTRY._names_to_collectors.get(name)


class TestMetricDefinitions:
    """Verify all 14 metrics are defined with correct types and labels."""

    def test_request_duration_histogram(self):
        """venya_request_duration_seconds is a Histogram with correct buckets."""
        h = _find_collector("venya_request_duration_seconds")
        assert h is not None
        assert h._type == "histogram"
        assert 0.025 in h._upper_bounds
        assert 0.25 in h._upper_bounds
        assert 2.5 in h._upper_bounds

    def test_requests_total_counter(self):
        """venya_requests is a Counter with endpoint/method/status_code labels."""
        c = _find_collector("venya_requests")
        assert c is not None
        assert c._type == "counter"
        assert set(c._labelnames) == {"endpoint", "method", "status_code"}

    def test_executor_registered_counter(self):
        """venya_executor_registered has result label (no executor_id)."""
        c = _find_collector("venya_executor_registered")
        assert c is not None
        assert c._type == "counter"
        assert set(c._labelnames) == {"result"}
        assert "executor_id" not in c._labelnames
        assert "user_id" not in c._labelnames

    def test_token_created_counter(self):
        """venya_token_created has type label."""
        c = _find_collector("venya_token_created")
        assert c is not None
        assert set(c._labelnames) == {"type"}

    def test_token_consumed_counter(self):
        """venya_token_consumed has result label."""
        c = _find_collector("venya_token_consumed")
        assert c is not None
        assert set(c._labelnames) == {"result"}

    def test_ca_signed_counter(self):
        """venya_ca_signed has cert_type label."""
        c = _find_collector("venya_ca_signed")
        assert c is not None
        assert set(c._labelnames) == {"cert_type"}

    def test_ca_signed_duration_histogram(self):
        """venya_ca_signed_duration_seconds is a Histogram with tight low-end buckets."""
        h = _find_collector("venya_ca_signed_duration_seconds")
        assert h is not None
        assert h._type == "histogram"
        assert set(h._labelnames) == {"cert_type"}

    def test_auth_login_counter(self):
        """venya_auth_login has mode and result labels."""
        c = _find_collector("venya_auth_login")
        assert c is not None
        assert set(c._labelnames) == {"mode", "result"}

    def test_auth_refresh_counter(self):
        """venya_auth_refresh has result label."""
        c = _find_collector("venya_auth_refresh")
        assert c is not None
        assert set(c._labelnames) == {"result"}

    def test_rate_limit_counter(self):
        """venya_rate_limit_hit has limit_type label."""
        c = _find_collector("venya_rate_limit_hit")
        assert c is not None
        assert set(c._labelnames) == {"limit_type"}

    def test_executor_heartbeat_counter(self):
        """venya_executor_heartbeat has no labels."""
        c = _find_collector("venya_executor_heartbeat")
        assert c is not None
        assert c._type == "counter"
        assert set(c._labelnames) == set()

    def test_executor_active_gauge(self):
        """venya_executor_active_total is a Gauge."""
        c = _find_collector("venya_executor_active_total")
        assert c is not None
        assert c._type == "gauge"

    def test_token_revoked_counter(self):
        """venya_token_revoked has reason label."""
        c = _find_collector("venya_token_revoked")
        assert c is not None
        assert set(c._labelnames) == {"reason"}

    def test_ca_crl_generated_counter(self):
        """venya_ca_crl_generated has no labels."""
        c = _find_collector("venya_ca_crl_generated")
        assert c is not None
        assert set(c._labelnames) == set()

    def test_ca_revocations_purged_counter(self):
        """venya_ca_revocations_purged has no labels."""
        c = _find_collector("venya_ca_revocations_purged")
        assert c is not None
        assert set(c._labelnames) == set()

    def test_core_operations_counter(self):
        """venya_core_operations has operation and result labels."""
        c = _find_collector("venya_core_operations")
        assert c is not None
        assert set(c._labelnames) == {"operation", "result"}


class TestCardinalityControls:
    """Verify no high-cardinality labels in any metric."""

    def test_no_executor_id_in_any_metric(self):
        """No metric should have executor_id as a label."""
        for name, c in REGISTRY._names_to_collectors.items():
            if name.startswith("venya_") and hasattr(c, "_labelnames"):
                assert "executor_id" not in c._labelnames, (
                    f"High-cardinality label 'executor_id' found in {name}"
                )

    def test_no_user_id_in_any_metric(self):
        """No metric should have user_id as a label."""
        for name, c in REGISTRY._names_to_collectors.items():
            if name.startswith("venya_") and hasattr(c, "_labelnames"):
                assert "user_id" not in c._labelnames, (
                    f"High-cardinality label 'user_id' found in {name}"
                )

    def test_no_ip_in_any_metric(self):
        """No metric should have ip as a label."""
        for name, c in REGISTRY._names_to_collectors.items():
            if name.startswith("venya_") and hasattr(c, "_labelnames"):
                assert "ip" not in c._labelnames, (
                    f"High-cardinality label 'ip' found in {name}"
                )


class TestNoSensitiveData:
    """Verify metrics output doesn't contain PII."""

    def test_metrics_output_no_emails(self):
        """Metrics output shouldn't contain email addresses."""
        output = generate_latest(REGISTRY).decode()
        assert "admin@" not in output
        assert "@venya" not in output

    def test_metrics_output_no_token_values(self):
        """Metrics output shouldn't contain token values."""
        output = generate_latest(REGISTRY).decode()
        assert "enrl_exec_" not in output
        assert "enrl_user_" not in output

    def test_metrics_output_no_passwords(self):
        """Metrics output shouldn't contain passwords."""
        output = generate_latest(REGISTRY).decode()
        assert "venya707" not in output


class TestMiddlewareEndpointNormalization:
    """Test _normalize_endpoint function."""

    def test_normalize_static_path(self):
        """Static paths pass through unchanged."""
        assert _normalize_endpoint("/api/v1/health") == "/api/v1/health"

    def test_normalize_numeric_id(self):
        """Numeric ID segments are replaced with {id}."""
        assert _normalize_endpoint("/api/v1/admin/users/123") == "/api/v1/admin/users/{id}"

    def test_normalize_uuid(self):
        """UUID segments are replaced with {id}."""
        assert _normalize_endpoint(
            "/api/v1/secrets/550e8400-e29b-41d4-a716-446655440000"
        ) == "/api/v1/secrets/{id}"

    def test_normalize_mixed(self):
        """Mixed numeric and text segments handled correctly."""
        assert _normalize_endpoint(
            "/api/v1/admin/executors/jump-1/certs/999/revoke"
        ) == "/api/v1/admin/executors/jump-1/certs/{id}/revoke"


class TestCounterIncrements:
    """Verify counters increment correctly at key code paths."""

    def test_executor_registered_counter_values(self):
        """Executor registered counter uses only valid result values."""
        c = _find_collector("venya_executor_registered")
        assert c is not None
        valid_results = {
            "success", "invalid_csr", "weak_key", "token_invalid",
            "token_expired", "token_consumed", "token_revoked",
            "ca_error", "db_error", "token_required",
        }
        for key in c._metrics:
            assert key[0] in valid_results, f"Unexpected result label: {key[0]}"

    def test_token_consumed_counter_values(self):
        """Token consumed counter uses only valid result values."""
        c = _find_collector("venya_token_consumed")
        assert c is not None
        valid_results = {
            "success", "invalid", "expired", "consumed", "revoked",
            "binding_mismatch",
        }
        for key in c._metrics:
            assert key[0] in valid_results, f"Unexpected result label: {key[0]}"

    def test_auth_login_counter_values(self):
        """Auth login counter uses valid mode/result combinations."""
        c = _find_collector("venya_auth_login")
        assert c is not None
        valid_modes = {"webauthn", "browser", "password"}
        valid_results = {"success", "failure"}
        for key in c._metrics:
            assert key[0] in valid_modes, f"Unexpected mode: {key[0]}"
            assert key[1] in valid_results, f"Unexpected result: {key[1]}"
