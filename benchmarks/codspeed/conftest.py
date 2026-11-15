"""Shared fixtures for the CodSpeed (pytest-codspeed) benchmarks.

Run locally with:

    uv run pytest benchmarks/codspeed --codspeed -n 0
"""

import numpy
import pandas
import pyarrow
import pytest
import stamina

from tiled.adapters.array import ArrayAdapter
from tiled.adapters.dataframe import DataFrameAdapter
from tiled.adapters.mapping import MapAdapter
from tiled.catalog import from_uri
from tiled.client import Context, from_context
from tiled.server.app import build_app

# Keep Arrow single-threaded so that measurements are not dominated by
# thread-pool synchronization.
pyarrow.set_cpu_count(1)
pyarrow.set_io_thread_count(1)


@pytest.fixture(autouse=True, scope="session")
def deactivate_retries():
    "Deactivate HTTP retries so that failures surface immediately."
    stamina.set_active(False)


@pytest.fixture(scope="module")
def map_client():
    "A client connected to an in-process server serving an in-memory tree."
    rng = numpy.random.default_rng(0)
    tree = MapAdapter(
        {
            "small_array": ArrayAdapter.from_array(numpy.arange(100)),
            "image": ArrayAdapter.from_array(rng.random((512, 512))),
            "table": DataFrameAdapter.from_pandas(
                pandas.DataFrame(
                    {
                        "a": numpy.arange(1_000),
                        "b": rng.random(1_000),
                        "c": [f"label-{i}" for i in range(1_000)],
                    }
                ),
                npartitions=1,
            ),
            **{
                f"node_{i:03}": ArrayAdapter.from_array(
                    numpy.ones(10), metadata={"index": i, "parity": i % 2}
                )
                for i in range(100)
            },
        }
    )
    with Context.from_app(build_app(tree)) as context:
        yield from_context(context)


@pytest.fixture
def catalog_client(tmp_path):
    "A client connected to an in-process server backed by a fresh SQLite catalog."
    catalog = from_uri(
        f"sqlite:///{tmp_path}/catalog.db",
        init_if_not_exists=True,
        writable_storage=str(tmp_path / "data"),
    )
    with Context.from_app(build_app(catalog)) as context:
        yield from_context(context)
