# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for the enrollment-manager TTL wiring (fido2-enrollment-ttl-config-dead).

Truth table: configured override is wired; default is 900 s; missing app-state
config falls back to the EnrollmentConfig default (keeps minimal test apps and
any config-less construction on the historical behavior).
"""

from datetime import timedelta
from types import SimpleNamespace

from server.dependencies import enrollment_manager


def _fake_request(ttl_minutes: int | None = None) -> SimpleNamespace:
    if ttl_minutes is None:
        state = SimpleNamespace()  # no config attribute at all
    else:
        state = SimpleNamespace(config=SimpleNamespace(fido2=SimpleNamespace(enrollment_token_ttl=ttl_minutes)))
    return SimpleNamespace(app=SimpleNamespace(state=state))


def test_ttl_override_is_wired() -> None:
    em = enrollment_manager(object(), _fake_request(240))  # type: ignore[arg-type]
    assert em.config.token_expiry == timedelta(minutes=240)
    # the value response literals derive from
    assert int(em.config.token_expiry.total_seconds()) == 14400


def test_ttl_default_negative() -> None:
    em = enrollment_manager(object(), _fake_request(15))  # type: ignore[arg-type]
    assert int(em.config.token_expiry.total_seconds()) == 900


def test_no_config_falls_back_to_default() -> None:
    em = enrollment_manager(object(), _fake_request(None))  # type: ignore[arg-type]
    assert em.config.token_expiry == timedelta(minutes=15)
