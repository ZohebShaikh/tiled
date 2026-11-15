"""Benchmarks for the server-side serializers and client-side deserializers."""

import numpy
import pandas
import pytest

from tiled.media_type_registration import (
    default_deserialization_registry,
    default_serialization_registry,
)
from tiled.serialization import register_builtin_serializers
from tiled.structures.core import StructureFamily
from tiled.utils import APACHE_ARROW_FILE_MIME_TYPE

register_builtin_serializers()


@pytest.fixture
def array():
    return numpy.random.default_rng(0).random((100, 100))


@pytest.fixture
def dataframe():
    rng = numpy.random.default_rng(0)
    return pandas.DataFrame(
        {
            "a": numpy.arange(1_000),
            "b": rng.random(1_000),
            "c": [f"label-{i}" for i in range(1_000)],
        }
    )


@pytest.mark.parametrize("mimetype", ["application/json", "text/csv"])
def test_serialize_array(benchmark, array, mimetype):
    serializer = default_serialization_registry.dispatch("array", mimetype)
    benchmark(serializer, mimetype, array, {})


@pytest.mark.parametrize(
    "mimetype", [APACHE_ARROW_FILE_MIME_TYPE, "application/x-parquet", "text/csv"]
)
def test_serialize_table(benchmark, dataframe, mimetype):
    serializer = default_serialization_registry.dispatch(
        StructureFamily.table, mimetype
    )
    benchmark(serializer, mimetype, dataframe, {})


def test_deserialize_table_arrow(benchmark, dataframe):
    serializer = default_serialization_registry.dispatch(
        StructureFamily.table, APACHE_ARROW_FILE_MIME_TYPE
    )
    deserializer = default_deserialization_registry.dispatch(
        StructureFamily.table, APACHE_ARROW_FILE_MIME_TYPE
    )
    buffer = bytes(serializer(APACHE_ARROW_FILE_MIME_TYPE, dataframe, {}))
    benchmark(deserializer, buffer)
