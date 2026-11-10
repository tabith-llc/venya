# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Venya core package."""

from core.version import release_version as _release_version

# Single-sourced from the installed distribution metadata (RELEASES.md §1 —
# kills the last non-derived version literal; surfaces read this string),
# rendered through the one canonical form so every layer says the same thing
# regardless of which build backend wrote its metadata.
__version__ = _release_version("core")
