"Round-trip formats through the serialization and deserialization registries."

import numpy
import pandas
import pytest

from tiled.media_type_registration import (
    default_deserialization_registry,
    default_serialization_registry,
)
from tiled.serialization import register_builtin_serializers
from tiled.utils import modules_available

register_builtin_serializers()

XLSX_MIME_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


@pytest.mark.parametrize(
    "media_type, module",
    [("image/png", "PIL"), ("image/tiff", "tifffile")],
)
def test_array_image_round_trip(media_type, module):
    if not modules_available(module):
        pytest.skip(f"{module} not installed")
    array = numpy.arange(12, dtype="uint8").reshape(3, 4)
    serialize = default_serialization_registry.dispatch("array", media_type)
    deserialize = default_deserialization_registry.dispatch("array", media_type)
    # Called the way the server's write paths call deserializers.
    result = deserialize(bytes(serialize(media_type, array, {})), "uint8", (3, 4))
    assert result.shape == (3, 4)
    assert result.dtype == numpy.uint8


def test_excel_round_trip():
    if not modules_available("openpyxl"):
        pytest.skip("openpyxl not installed")
    df = pandas.DataFrame({"a": [1, 2]})
    serialize = default_serialization_registry.dispatch("table", XLSX_MIME_TYPE)
    deserialize = default_deserialization_registry.dispatch("table", XLSX_MIME_TYPE)
    result = deserialize(bytes(serialize(XLSX_MIME_TYPE, df, {})))
    pandas.testing.assert_frame_equal(result, df)


@pytest.mark.parametrize(
    "media_type",
    ["application/x-parquet", "text/csv", "text/plain", "text/html", XLSX_MIME_TYPE],
)
def test_sparse_tabular_serializers(media_type):
    sparse = pytest.importorskip("sparse")
    if media_type == XLSX_MIME_TYPE and not modules_available("openpyxl"):
        pytest.skip("openpyxl not installed")
    arr = sparse.COO.from_numpy(numpy.eye(3))
    serialize = default_serialization_registry.dispatch("sparse", media_type)
    assert len(bytes(serialize(media_type, arr, {}))) > 0
