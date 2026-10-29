import contextlib
from collections.abc import Sequence
from typing import Any, cast

import dask.array
import numpy
import pandas
from numpy.typing import ArrayLike, NDArray

from tiled.adapters.core import Adapter

from ..ndslice import NDBlock, NDSlice
from ..structures.array import ArrayStructure
from ..structures.core import Spec, StructureFamily
from ..type_aliases import JSON, ArrayLikeObject, Chunks
from .utils import force_reshape


class ArrayAdapter(Adapter[ArrayStructure]):
    """
    Wrap an array-like object in an interface that Tiled can serve.

    Examples
    --------

    Wrap any array-like.

    >>> ArrayAdapter.from_array(numpy.random.random((100, 100)))

    >>> ArrayAdapter.from_array(dask.array.from_array(numpy.random.random((100, 100)), chunks=(100, 50)))

    """

    structure_family = StructureFamily.array

    def __init__(
        self,
        array: ArrayLikeObject,
        structure: ArrayStructure,
        *,
        metadata: JSON | None = None,
        specs: list[Spec] | None = None,
    ) -> None:
        self._array = array
        super().__init__(structure, metadata=metadata, specs=specs)

    @classmethod
    def from_array(
        cls,
        array: ArrayLike,
        *,
        shape: tuple[int, ...] | None = None,
        chunks: Chunks | None = None,
        dims: tuple[str, ...] | None = None,
        metadata: JSON | None = None,
        specs: list[Spec] | None = None,
    ) -> "ArrayAdapter":
        # May be a list of something; convert to array
        if not isinstance(array, ArrayLikeObject):
            array = numpy.asanyarray(array)

        # Convert array of arrays to ND array to expose the underlying dtype
        is_array_of_arrays = (
            array.dtype == numpy.dtype(object)
            and array.shape[0]
            and isinstance(array[0], numpy.ndarray)
        )
        if is_array_of_arrays:
            with contextlib.suppress(ValueError):
                # only uniform arrays (with same dimensions) are stackable
                array = numpy.vstack(cast("Sequence[numpy.ndarray]", array))

        # Convert (experimental) pandas.StringDtype to numpy's unicode string dtype
        is_likely_string_dtype = isinstance(array.dtype, pandas.StringDtype) or (
            array.dtype == numpy.dtype(object) and array.dtype.fields is None
        )
        if is_likely_string_dtype:
            array = numpy.array([str(x) for x in array])  # becomes "<Un" dtype

        structure = ArrayStructure.from_array(
            array, shape=shape, chunks=chunks, dims=dims
        )
        return cls(
            array,
            structure=structure,
            metadata=metadata,
            specs=specs,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._array!r})"

    @property
    def dims(self) -> tuple[str, ...] | None:
        return self._structure.dims

    def read(
        self,
        slice: NDSlice = NDSlice(...),
    ) -> NDArray[Any]:
        array = force_reshape(self._array, self._structure.shape)
        # _array[...] requires an actual tuple, not just a subclass of tuple
        result = array[tuple(slice)] if slice else array
        if isinstance(result, dask.array.Array):
            return result.compute()
        return numpy.asanyarray(result)

    def read_block(
        self,
        block: NDBlock,
        slice: NDSlice = NDSlice(...),
    ) -> NDArray[Any]:
        # Slice the whole array to get this block.
        array = force_reshape(self._array, self._structure.shape)
        slice_ = block.slice_from_chunks(self._structure.chunks)
        # _array[...] requires an actual tuple, not just a subclass of tuple
        block_array = array[tuple(slice_)]
        # Slice within the block.
        result = block_array[slice] if slice else block_array
        if isinstance(result, dask.array.Array):
            return result.compute()
        return numpy.asanyarray(result)
