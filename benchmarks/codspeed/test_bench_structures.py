"""Benchmarks for building and (de)serializing structure descriptions."""

import dataclasses

import numpy
import pandas
import pytest

from tiled.structures.array import ArrayStructure
from tiled.structures.table import TableStructure

STRUCT_DTYPE = numpy.dtype(
    [("x", "<f8"), ("y", "<i4"), ("flags", "u1", (4,)), ("name", "S16")]
)


@pytest.fixture
def dataframe():
    return pandas.DataFrame(
        {
            **{f"float_{i}": numpy.arange(100, dtype=float) for i in range(20)},
            **{f"int_{i}": numpy.arange(100) for i in range(20)},
            "label": [f"row-{i}" for i in range(100)],
        }
    )


@pytest.mark.benchmark
def test_array_structure_json_roundtrip():
    arrays = [
        numpy.zeros((10, 20, 30)),
        numpy.zeros(100, dtype=STRUCT_DTYPE),
        numpy.zeros((5, 5), dtype="<M8[ns]"),
    ]
    for _ in range(50):
        for arr in arrays:
            structure = ArrayStructure.from_array(arr)
            ArrayStructure.from_json(dataclasses.asdict(structure))


def test_table_structure_from_pandas(benchmark, dataframe):
    benchmark(TableStructure.from_pandas, dataframe)


def test_table_structure_json_roundtrip(benchmark, dataframe):
    structure = TableStructure.from_pandas(dataframe)
    as_dict = dataclasses.asdict(structure)

    @benchmark
    def roundtrip():
        TableStructure.from_json(as_dict).arrow_schema_decoded
