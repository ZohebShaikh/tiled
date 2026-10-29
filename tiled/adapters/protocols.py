from abc import abstractmethod
from collections.abc import Set as AbstractSet
from typing import Any, Literal, Protocol

import dask.dataframe
import pandas
import ragged
import sparse
from numpy.typing import NDArray

from tiled.structures.ragged import RaggedStructure

from ..ndslice import NDBlock, NDSlice
from ..storage import Storage
from ..structures.array import ArrayStructure
from ..structures.awkward import AwkwardStructure
from ..structures.bytes import BytesStructure
from ..structures.core import Spec, StructureFamily
from ..structures.sparse import SparseStructure
from ..structures.table import TableStructure
from ..type_aliases import JSON
from .container import ContainerAdapter


class BaseAdapter(Protocol):
    @classmethod
    def supported_storage(cls) -> AbstractSet[type[Storage]]: ...

    @abstractmethod
    def metadata(self) -> JSON:
        pass

    @property
    def specs(self) -> list[Spec]: ...


class ArrayAdapter(BaseAdapter, Protocol):
    structure_family: Literal[StructureFamily.array]

    @abstractmethod
    def structure(self) -> ArrayStructure:
        pass

    @abstractmethod
    def read(self, slice: NDSlice = NDSlice(...)) -> NDArray[Any]:
        pass

    @abstractmethod
    def read_block(self, block: NDBlock, slice: NDSlice = NDSlice(...)) -> NDArray[Any]:
        pass


class AwkwardAdapter(BaseAdapter, Protocol):
    structure_family: Literal[StructureFamily.awkward]

    @abstractmethod
    def structure(self) -> AwkwardStructure:
        pass

    @abstractmethod
    def read(self) -> NDArray[Any]:
        pass

    @abstractmethod
    def read_buffers(self, form_keys: list[str] | None = None) -> dict[str, Any]:
        pass


class RaggedAdapter(BaseAdapter, Protocol):
    structure_family: Literal[StructureFamily.ragged]

    @abstractmethod
    def structure(self) -> RaggedStructure:
        pass

    @abstractmethod
    def read(self, slice: NDSlice | None = None) -> ragged.array:
        pass


class SparseAdapter(BaseAdapter, Protocol):
    structure_family: Literal[StructureFamily.sparse] = StructureFamily.sparse

    @abstractmethod
    def structure(self) -> SparseStructure:
        pass

    @abstractmethod
    def read(self, slice: NDSlice = NDSlice(...)) -> sparse.COO:
        pass

    @abstractmethod
    def read_block(self, block: NDBlock, slice: NDSlice = NDSlice(...)) -> sparse.COO:
        pass


class TableAdapter(BaseAdapter, Protocol):
    structure_family: Literal[StructureFamily.table] = StructureFamily.table

    @abstractmethod
    def structure(self) -> TableStructure:
        pass

    @abstractmethod
    def read(
        self, fields: list[str] | None = None
    ) -> dask.dataframe.DataFrame | pandas.DataFrame:
        pass

    @abstractmethod
    def read_partition(
        self,
        partition: int,
        fields: str | None = None,
    ) -> dask.dataframe.DataFrame | pandas.DataFrame:
        pass

    @abstractmethod
    def __getitem__(self, key: str) -> ArrayAdapter:
        pass


class BytesAdapter(BaseAdapter, Protocol):
    structure_family: Literal[StructureFamily.bytes] = StructureFamily.bytes

    @abstractmethod
    def structure(self) -> BytesStructure:
        pass


AnyAdapter = (
    ArrayAdapter
    | AwkwardAdapter
    | BytesAdapter
    | ContainerAdapter[Any]
    | RaggedAdapter
    | SparseAdapter
    | TableAdapter
)
