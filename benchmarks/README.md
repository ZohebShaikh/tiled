# Tiled Benchmarks

Timings of common operations (reading, writing, searching, bulk tree
operations, serialization) against a Tiled server backed by PostgreSQL.

## Running locally

The suite needs a PostgreSQL server. As for the test suite, point
`TILED_TEST_POSTGRESQL_URI` at it; the suite creates and drops a database of
its own.

```bash
export TILED_TEST_POSTGRESQL_URI=postgresql://postgres:secret@localhost:5432
pytest -c benchmarks/pytest.ini --codspeed            # all, about 5 minutes
pytest -c benchmarks/pytest.ini --codspeed benchmarks/bench_search.py -k eq
```

Measurement is done by [pytest-codspeed](https://codspeed.io/docs/reference/pytest-codspeed),
whose `benchmark` fixture is compatible with pytest-benchmark's. In CI
(`.github/workflows/codspeed.yml`) the suite runs under CodSpeed's CPU
simulation, which reports the change against the base branch on every pull
request. Without `--codspeed`, each benchmark runs once, as a test.

## Writing a benchmark

Benchmarks are pytest functions named `bench_*` in `bench_*.py` files that
take the `benchmark` fixture, one operation per function:

```python
def bench_lookup(benchmark, client):
    benchmark(lambda: client["small"]["node_000500"])
```

`benchmark` calls the function repeatedly and records the timings. For an
operation that must not repeat on the same input (writes), use
`benchmark.pedantic` with a `setup` that produces fresh arguments for every
round, and write into the `scratch` fixture, which is deleted afterwards:

```python
def bench_create_container(benchmark, scratch):
    benchmark.pedantic(
        lambda key: scratch.create_container(key=key),
        setup=lambda: ((uuid.uuid4().hex,), {}),
        rounds=20,
    )
```

The populated catalog that benchmarks run against is described in
`conftest.py` (`populated`, `client`). It is built once per session, so a
benchmark must not change the size of its collections: write under
`scratch`, and read anywhere.

Keep a benchmark's name stable: CodSpeed identifies a series by it, and a
renamed benchmark starts a new series.
