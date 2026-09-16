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
| PostgreSQL 16 | PostgreSQL License | core installer | database |
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

License identifiers verified 2026-09-15 against installed package metadata
(cryptography 50.0.0, SQLAlchemy 2.0.51, pydantic 2.13.4, fido2 2.2.1, httpx2 2.12.0,
FastAPI 0.141.1, uvicorn 0.52.1, websockets 17.0.1, prometheus-client 0.26.0,
mcp 1.29.1, docker-sbx 0.38.0). This file is informational, not legal advice;
the upstream license texts govern.
