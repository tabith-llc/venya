# Third-Party Notices

Venya itself is licensed under the Business Source License 1.1 — see [LICENSE](LICENSE).
This file lists the third-party components Venya depends on at install time and runtime.
**Venya does not bundle or redistribute any of them.** The installers fetch each component
from its official source (Docker's apt repository, PyPI, Ubuntu archives) at install time.
Each component remains governed by its own license and terms.

## Docker Sandboxes (sbx) — REQUIRED, PROPRIETARY

Venya's sandboxed command execution requires **Docker Sandboxes (`sbx`)**, a **proprietary**
product of Docker, Inc.

- **License:** Proprietary. Use is subject to the
  [Docker Subscription Service Agreement](https://www.docker.com/legal/docker-subscription-service-agreement)
  (per the package copyright file; Copyright 2026 Docker, Inc.).
- **Distribution:** the Venya executor installer fetches `docker-sbx` from Docker's
  official apt repository. The package is NOT bundled with or redistributed by Venya.
- **Docker account required:** installation and operation of sbx require a Docker account
  (username + API key/access token) — sbx pulls its agent template from Docker.
- **Hardware virtualization required:** sbx runs each sandbox as a microVM via the host's
  virtualization layer (on Linux, `/dev/kvm` — the Venya executor installer adds its
  service account to the `kvm` group). VM deployments require nested virtualization
  enabled; without it the executor install completes but sandboxed execution fails.
- **Its own third-party components:** the `docker-sbx` package ships its own
  `THIRD-PARTY-NOTICES` file (including the GPL-2.0 Linux kernel, erofs-utils, e2fsprogs,
  crun, and containerd components). Docker, Inc. offers corresponding source for the
  GPL-licensed components therein.

**Installing a Venya executor means accepting Docker's terms for sbx.** Verify that your
organization's agreement with Docker, Inc. covers your intended use before deploying.

## System components (installed from official repositories)

| Component | License | Installed by | Purpose |
|-----------|---------|--------------|---------|
| nginx | BSD-2-Clause | core installer | reverse proxy / TLS termination |
| PostgreSQL | PostgreSQL License | core installer | database (major version from the distro archive — see the inventory) |
| Docker CE, containerd, Buildx, Compose | Apache-2.0 | executor installer | container engine |
| uv | MIT OR Apache-2.0 | all installers | Python package / tool manager |
| Python 3.14 | PSF-2.0 | provisioned via uv | runtime |
| Rust toolchain | MIT OR Apache-2.0 | executor installer | builds the output-filter extension |

## Python libraries (fetched from PyPI at install time)

Direct dependencies of the Venya packages. Exact resolved versions are pinned in
[uv.lock](uv.lock); transitive dependencies ship with their own license metadata.

| Package | License |
|---------|---------|
| cryptography | Apache-2.0 OR BSD-3-Clause |
| argon2-cffi | MIT |
| pycryptodome | BSD-2-Clause (portions public domain) |
| SQLAlchemy | MIT |
| psycopg2-binary | LGPL-3.0-or-later (with exceptions) |
| Alembic | MIT |
| pydantic | MIT |
| pydantic-settings | MIT |
| fido2 | BSD-2-Clause OR Apache-2.0 OR MPL-2.0 |
| httpx2 | BSD-3-Clause |
| FastAPI | MIT |
| uvicorn | BSD-3-Clause |
| websockets | BSD-3-Clause |
| prometheus-client | Apache-2.0 AND BSD-2-Clause |
| tomli-w | MIT |
| mcp | MIT |

## Rust crates (venya-filter output-redaction extension)

| Crate | License |
|-------|---------|
| pyo3 | MIT OR Apache-2.0 |
| sha2 | MIT OR Apache-2.0 |
| base64 | MIT OR Apache-2.0 |
| hex | MIT OR Apache-2.0 |

---

License identifiers verified 2026-09-15 against installed package metadata.
Version numbers are NOT verified here and are not listed here: they are derived at release
time by `scripts/gen_third_party_notices.py` and printed in the inventory below. A version typed into
this file outside that inventory is a defect — the release gate refuses to tag on one.

<!-- BEGIN GENERATED DEPENDENCY INVENTORY (scripts/gen_third_party_notices.py) -->

## Dependency versions this release ships (generated)

This block is written by `scripts/gen_third_party_notices.py`. Do not edit a number here;
edit the source the row names and regenerate. A version in this file that is not in this
block and not backed by a command below is a defect the release gate refuses to tag.

### Locked — resolved from the lock files in this tree

| Component | Version | How to re-derive |
|-----------|---------|------------------|
| alembic | `1.18.5` | `grep -A1 '^name = "alembic"$' uv.lock` |
| argon2-cffi | `25.1.0` | `grep -A1 '^name = "argon2-cffi"$' uv.lock` |
| base64 | `0.22.1` | `grep -A1 '^name = "base64"$' packages/executor/Cargo.lock` |
| cryptography | `50.0.0` | `grep -A1 '^name = "cryptography"$' uv.lock` |
| fastapi | `0.141.1` | `grep -A1 '^name = "fastapi"$' uv.lock` |
| fido2 | `2.2.1` | `grep -A1 '^name = "fido2"$' uv.lock` |
| hex | `0.4.3` | `grep -A1 '^name = "hex"$' packages/executor/Cargo.lock` |
| httpx2 | `2.12.0` | `grep -A1 '^name = "httpx2"$' uv.lock` |
| mcp | `1.29.1` | `grep -A1 '^name = "mcp"$' uv.lock` |
| prometheus-client | `0.26.0` | `grep -A1 '^name = "prometheus-client"$' uv.lock` |
| psycopg2-binary | `2.9.12` | `grep -A1 '^name = "psycopg2-binary"$' uv.lock` |
| pycryptodome | `3.23.0` | `grep -A1 '^name = "pycryptodome"$' uv.lock` |
| pydantic | `2.13.4` | `grep -A1 '^name = "pydantic"$' uv.lock` |
| pydantic-settings | `2.14.2` | `grep -A1 '^name = "pydantic-settings"$' uv.lock` |
| pyo3 | `0.25.1` | `grep -A1 '^name = "pyo3"$' packages/executor/Cargo.lock` |
| python | `==3.14.*` | `grep '^requires-python' uv.lock` |
| sha2 | `0.10.9` | `grep -A1 '^name = "sha2"$' packages/executor/Cargo.lock` |
| sqlalchemy | `2.0.51` | `grep -A1 '^name = "sqlalchemy"$' uv.lock` |
| tomli-w | `1.2.0` | `grep -A1 '^name = "tomli-w"$' uv.lock` |
| uvicorn | `0.52.1` | `grep -A1 '^name = "uvicorn"$' uv.lock` |
| venya-filter | `0.2.0` | `grep '^version' packages/executor/Cargo.toml` |
| websockets | `17.0.1` | `grep -A1 '^name = "websockets"$' uv.lock` |

### Floored — the vendor package is fetched from a floating repository

For these the release ships a MINIMUM, not a number. The installed version is whatever the
vendor's repository serves on the day of the install.

| Component | Floor enforced | How to read the installed version |
|-----------|----------------|-----------------------------------|
| docker-sbx | `0.39.0` | `dpkg-query -W -f='${Version}' docker-sbx` |
| rust-toolchain | `1.80` | `grep '^rust-version' packages/executor/Cargo.toml` |

### Install-time only — no version is knowable at build time

| Component | Why | How to read it on a machine |
|-----------|-----|-----------------------------|
| docker-ce | distro/vendor package, not locked by Venya | `dpkg-query -W -f='${Version}' docker-ce + dpkg-query -W -f='${Version}' docker-ce-cli + dpkg-query -W -f='${Version}' containerd.io + dpkg-query -W -f='${Version}' docker-buildx-plugin` |
| nginx | distro/vendor package, not locked by Venya | `dpkg-query -W -f='${Version}' nginx` |
| postgresql | distro/vendor package, not locked by Venya | `dpkg-query -W -f='${Version}' postgresql` |
| uv | distro/vendor package, not locked by Venya | `uv --version` |

**The boundary that produced the defect this block replaces:** `docker-sbx` is not in
`uv.lock` and is not in any lock file. It is a Docker apt package pulled from
`get.docker.com`'s floating repository, so a dependency inventory that reads only the Python
lock cannot see it move. Its row above is the floor the installer enforces, read from that
installer, not a version anybody typed.

<!-- END GENERATED DEPENDENCY INVENTORY -->
