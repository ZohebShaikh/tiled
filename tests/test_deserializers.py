"Round-trip formats through the serialization and deserialization registries."

import numpy
import pandas
import pytest

from tiled.media_type_registration import (
    default_deserialization_registry,
    default_serialization_registry,
)
from tiled.serialization import register_builtin_serializers
from tiled.utils import XLSX_MIME_TYPE, modules_available

register_builtin_serializers()


@pytest.mark.parametrize(
    "media_type, module",
    [("image/png", "PIL"), ("image/tiff", "tifffile")],
)
def test_array_image_round_trip(media_type, module):
    if not modules_available(module):
        pytest.skip(f"{module} not installed")
    # The PNG serializer auto-scales values, so check shape and dtype only.
    array = numpy.arange(12, dtype="uint8").reshape(3, 4)
    serialize = default_serialization_registry.dispatch("array", media_type)
    deserialize = default_deserialization_registry.dispatch("array", media_type)
    # Called the way the server's write paths call array deserializers.
    result = deserialize(bytes(serialize(media_type, array, {})), "uint8", (3, 4))
    assert result.shape == (3, 4)
    assert result.dtype == numpy.uint8


def test_excel_round_trip():
    if not modules_available("openpyxl"):
        pytest.skip("openpyxl not installed")
    df = pandas.DataFrame({"a": [1, 2]})
    serialize = default_serialization_registry.dispatch("table", XLSX_MIME_TYPE)
    deserialize = default_deserialization_registry.dispatch("table", XLSX_MIME_TYPE)
    # Called the way the server's streaming path calls table deserializers.
    result = deserialize(bytes(serialize(XLSX_MIME_TYPE, df, {})))
    pandas.testing.assert_frame_equal(result, df)


def test_csv_round_trip():
    df = pandas.DataFrame({"a": [1, 2]})
    serialize = default_serialization_registry.dispatch("table", "text/csv")
    deserialize = default_deserialization_registry.dispatch("table", "text/csv")
    # The CSV deserializer reads headerless rows.
    payload = bytes(serialize("text/csv;header=absent", df, {}))
    result = deserialize(payload)
    assert result[0].tolist() == [1, 2]
