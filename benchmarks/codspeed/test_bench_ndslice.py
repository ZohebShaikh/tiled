"""Benchmarks for N-dimensional slice parsing and composition."""

import pytest

from tiled.ndslice import NDSlice

NUMPY_STRS = [
    "0",
    ":,3",
    "1:10:2,::3,-5:",
    "...,0:100,5",
    "10:20,30:40,50:60,70:80",
]


@pytest.mark.benchmark
def test_ndslice_from_numpy_str():
    for _ in range(100):
        for s in NUMPY_STRS:
            NDSlice.from_numpy_str(s)


@pytest.mark.benchmark
def test_ndslice_json_roundtrip():
    slices = [NDSlice.from_numpy_str(s) for s in NUMPY_STRS]
    for _ in range(100):
        for slc in slices:
            NDSlice.from_json(slc.to_json(ndim=6))


@pytest.mark.benchmark
def test_ndslice_compose_and_expand():
    outer = NDSlice.from_numpy_str("10:1000:2,::3,5:")
    inner = NDSlice.from_numpy_str("1:100:3,2:50,::2")
    shape = (2000, 300, 400)
    for _ in range(100):
        outer.expand_for_shape(shape)[inner]
