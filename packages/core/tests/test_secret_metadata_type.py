# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Regression test: Secret.metadata must be JSONB on PostgreSQL.

Migration 023 adds a GIN index on the column. GIN only works on jsonb,
never on the plain json type. The generic sa.JSON() renders to Postgres
"json", which has no GIN operator class, so the column must be
postgresql.JSONB on the PostgreSQL dialect. Reverting the model to plain
JSON would silently drop JSONB and break fresh installs -- alembic upgrade
head fails on the GIN index with:
    data type json has no default operator class for access method "gin"
"""

from core.iam.models import Secret
from sqlalchemy.dialects import postgresql, sqlite


def _metadata_column_type_compile(dialect) -> str:
    return str(Secret.__table__.c["metadata"].type.compile(dialect=dialect))


def test_secret_metadata_is_jsonb_on_postgresql():
    assert _metadata_column_type_compile(postgresql.dialect()) == "JSONB"


def test_secret_metadata_is_json_on_sqlite():
    # The with_variant form must still render plain JSON off-PostgreSQL so
    # the SQLite test suites (create_all) keep working.
    assert _metadata_column_type_compile(sqlite.dialect()) == "JSON"
