"""End-to-end benchmarks: a Python client talking to an in-process Tiled server."""

import numpy

from tiled.queries import Key


def test_list_keys(benchmark, map_client):
    benchmark(lambda: list(map_client))


def test_lookup(benchmark, map_client):
    benchmark(lambda: map_client["small_array"])


def test_read_array(benchmark, map_client):
    node = map_client["image"]
    benchmark(node.read)


def test_read_array_slice(benchmark, map_client):
    node = map_client["image"]
    benchmark(lambda: node[100:200, ::4])


def test_read_table(benchmark, map_client):
    node = map_client["table"]
    benchmark(node.read)


def test_search_metadata(benchmark, map_client):
    benchmark(lambda: list(map_client.search(Key("parity") == 1)))


def test_catalog_write_array(benchmark, catalog_client):
    arr = numpy.ones((100, 100))
    counter = iter(range(1_000_000))
    benchmark(lambda: catalog_client.write_array(arr, key=f"x{next(counter)}"))
