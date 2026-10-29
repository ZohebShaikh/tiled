import numpy
import pytest

from tiled.media_type_registration import default_serialization_registry
from tiled.serialization import register_builtin_serializers
from tiled.utils import XLSX_MIME_TYPE, modules_available

register_builtin_serializers()


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
