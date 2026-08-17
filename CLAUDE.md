# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Tiled is a service for secure, structured access to scientific data: search, remote
slicing, format conversion, and streaming. It's a Python server (FastAPI/Starlette) plus
a Python client, with an optional React web frontend (`web-frontend/`) served at `/ui/`.

## Environment and commands

This project uses `uv`. Do not use bare `pip`/`venv`.

```bash
uv sync --all-extras          # install everything (server + client + docs + test deps)
uv sync                       # minimal install
```

### Tests (Python)

```bash
uv run pytest -v                                   # full suite
uv run pytest tests/test_client.py -v               # one file
uv run pytest tests/test_client.py::test_name -v     # one test
uv run pytest -k "keyword"                           # by keyword
```

- `pytest.ini` sets `-n auto --dist=loadfile` (parallel via `pytest-xdist`) and `asyncio_mode = auto`.
- Some tests are opt-in and gated by env vars / running services, matching what CI sets up
  (see `.github/workflows/ci.yml` and `continuous_integration/scripts/`):
  `TILED_TEST_POSTGRESQL_URI`, `TILED_TEST_REDIS`, `TILED_TEST_BUCKET` (MinIO), `TILED_TEST_LDAP`.
  Without these, PostgreSQL/Redis/S3/LDAP-backed tests are skipped or fall back to SQLite/in-memory.
- CI downloads example SQLite/Postgres catalog databases and runs
  `tiled catalog upgrade-database <uri>` before testing — needed if you touch catalog/alembic migrations.

### Lint / static checks

Pre-commit (`.pre-commit-config.yaml`) runs: `flake8`, `isort`, `black`, `mypy --strict`
(plus trailing-whitespace/end-of-file/yaml/ast checks). Run it directly:

```bash
uv run pre-commit run --all-files
```

`black` config in `pyproject.toml` excludes `web-frontend/`, `tiled/_version.py`, and
generated/vendored files.

### Web frontend (`web-frontend/`)

```bash
cd web-frontend
npm install
npm run dev          # or `npm run serve`, launches at http://localhost:5173
npm run test:run      # vitest, single run
npm run test-watch    # vitest, watch mode
npm run type-check    # tsc --noEmit
```

To develop against a live backend, start a server that allows CORS from the Vite dev
server, then run the frontend separately:

```bash
TILED_ALLOW_ORIGINS='["http://localhost:5173"]' tiled serve demo --public
```

`vite.config.js` proxies `/api`, `/custom`, and `/tiled-ui-settings` to `127.0.0.1:8407`
when running the built-in dev proxy target — adjust if your server binds elsewhere.
The production build hook (`hatch_build.py`) builds the UI and copies it into
`share/tiled/ui`, bundled into the Python package as data (set `TILED_BUILD_SKIP_UI=1`
to skip this, e.g. on Windows CI).

To regenerate the OpenAPI-derived TypeScript types after changing server schemas:

```bash
npx openapi-typescript http://localhost:8000/openapi.json --output ./src/openapi_schemas.ts
```

### Running a server locally

```bash
tiled serve demo --public                 # in-memory demo data, no auth
tiled serve directory <path> --public      # serve a directory of files
tiled serve catalog <database-uri> ...     # SQL-catalog-backed server (writable, searchable)
```

Service-wide configuration (auth, access control, trees to mount, storage backends) is
driven by YAML validated against `tiled/config_schemas/service_configuration.yml` and
parsed by `tiled/config.py` (`Config`, `parse_configs`). See `example_configs/` for
worked examples (OIDC/Keycloak, access tags, bucket storage, custom formats, graphs).

## Architecture

The authoritative overview lives in `docs/source/explanations/architecture.md` — read it
for the canonical description. Summary:

**Client** (`tiled/client/`) — a Python client that lets users navigate/slice remote data
with familiar item-lookup and slicing idioms, translating that into HTTP requests.
A `Context` (`tiled/client/context.py`) wraps an `httpx` client (connection pool + auth
state — API key or OAuth2 tokens) and is shared by all client objects on a connection.
Optional client-side HTTP response caching lives in `tiled/client/cache.py`.

**Server** (`tiled/server/`) — FastAPI/Starlette app. `app.py` builds the app
(`build_app`, `build_app_from_config`); `router.py` defines the HTTP API; `dependencies.py`
holds FastAPI dependency-injected request context (current principal, scopes, etc.);
`authentication.py` implements the auth flows. OpenAPI docs are auto-served at `GET /docs`.

- **Authentication**: single-user deployments use one API key; multi-user deployments use
  an Authentication Database (Postgres/SQLite, `tiled/authn_database/`) for sessions and
  API key validation, plus pluggable `Authenticator`s (`tiled/authenticators.py`) for
  OIDC/LDAP/SAML/etc. External identity providers are configured per-deployment (see
  `example_configs/keycloak_oidc/`, `example_configs/simple_oidc/`).
- **Authorization**: scope-based. Canonical scope list is `tiled/access_control/scopes.py`
  (`SCOPES`, `PUBLIC_SCOPES`, `SINGLE_USER_SCOPES`). `AccessPolicy` implementations
  (`tiled/access_control/access_policies.py`) decide which scopes a principal has on a
  given node; access tags (`access_tags.py`) allow tag-based policies. A PDP
  (policy decision point) can be plugged in externally — see
  `example_configs/keycloak_oidc/tiled_policy/example_pdp.py`.
- **Accessing data/metadata**: endpoints resolve the URL path to an **Adapter**, which
  returns data as a scientific data structure — often lazily, loaded on demand and
  piecemeal (blockwise for arrays, partition-wise for tables).
- **Content negotiation & Serializers**: endpoints compare client-accepted formats against
  server-supported formats for the given structure, then dispatch to a registered
  Serializer (`tiled/media_type_registration.py`) to encode the response; compression is
  negotiated separately (`tiled/server/compression.py`).

**Adapter** (`tiled/adapters/`) — the abstraction over "how to get the data," independent
of storage. Different structure families have different Adapter interfaces (e.g. array
adapters implement `read_block`; table adapters implement `read_partition`), but all
adapters of a given family are interchangeable. Built-in adapters cover arrays, dataframes,
Zarr, HDF5, CSV, Excel, Parquet, TIFF/JPEG, netCDF, Awkward/ragged/sparse structures, and
plain in-memory data. Adapters can also be defined in external packages and registered via
entry points — they operate on equal footing with built-ins.

**Structures** (`tiled/structures/`) — the structure-family type definitions (array, table,
container, awkward, sparse, ragged, bytes) shared between client and server for describing
shape/dtype/schema over the wire.

**Catalog** (`tiled/catalog/`) — a specific Adapter that stores metadata/structure for many
datasets in a SQL database (Postgres or SQLite), enabling fast metadata/search without
opening data files; actual data reads are dispatched down to the relevant Adapter. Not
every deployment uses the Catalog — small/demo deployments can wrap Adapters directly with
no database. Catalog schema migrations use Alembic (`tiled/catalog/migrations/`,
`alembic.ini.template`); the separate Authentication Database has its own Alembic setup
under `tiled/authn_database/migrations/`.

**Commandline** (`tiled/commandline/`) — the `tiled` Typer CLI (`main.py`), including
`tiled serve directory|catalog|demo` (`_serve.py`), `tiled catalog ...` (`_catalog.py`,
DB migrations), `tiled admin ...`, and API key management.

## Repository layout notes

- `tests/` mirrors the package roughly 1:1 by feature area (e.g. `test_authentication.py`,
  `test_access_policy.py`, `test_catalog.py`); `tests/adapters/` and `tests/sql/` hold
  adapter- and SQL-specific tests. `tests/conftest.py` has the shared fixtures, including
  ones that spin up Postgres/Redis/MinIO-backed test apps when those services are available.
- `docs/source/explanations/` — design rationale (architecture, access control, catalog,
  caching, structures, security). Read these before making architectural changes.
- `docs/source/reference/` and `docs/source/user-guide/` — user-facing API/config reference
  and how-to guides (authentication, scopes, deployment, service configuration).
- `example_configs/` — runnable example service configurations for various deployment
  shapes (OIDC/Keycloak auth, access tags, bucket storage, custom export formats, graphs).
- `helm/` — Helm chart for Kubernetes deployment.
- `web-frontend/` — the built-in React UI, a separate npm project (see above); excluded
  from Python's black/isort/mypy checks.
