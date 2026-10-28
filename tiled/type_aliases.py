import sys

from pydantic import AfterValidator

if sys.version_info < (3, 10):
    EllipsisType = type(Ellipsis)
else:
    from types import EllipsisType

from typing import (
    AbstractSet,
    Annotated,
    Any,
    Callable,
    Coroutine,
    FrozenSet,
    List,
    Mapping,
    Protocol,
    Sequence,
    Tuple,
    TypedDict,
    Union,
    runtime_checkable,
)

from .utils import Sentinel, import_object

JSON_ITEM = Union[
    str, int, float, Mapping[str, "JSON_ITEM"], Sequence["JSON_ITEM"], None
]
JSON = Mapping[str, JSON_ITEM]

AccessTags = FrozenSet[str]
Scopes = AbstractSet[str]
Query = Any  # for now...
# A list of queries, or the NO_ACCESS sentinel (access_control.access_policies)
Filters = Union[List[Query], Sentinel]
Chunks = Tuple[Tuple[int, ...], ...]


@runtime_checkable
class ArrayLikeObject(Protocol):
    "An array object (numpy, dask, zarr, h5py, ...) that can back an ArrayAdapter."

    # Any rather than Tuple[int, ...]: dask uses NaN for unknown dimensions,
    # and declares shape with its own cached_property descriptor.
    @property
    def shape(self) -> Any: ...

    @property
    def dtype(self) -> Any: ...

    def __getitem__(self, key: Any, /) -> Any: ...

    def __array__(self) -> Any: ...


AppTask = Callable[[], Coroutine[None, None, Any]]
"""Async function to be run as part of the app's lifecycle"""


class TaskMap(TypedDict):
    background: list[AppTask]
    startup: list[AppTask]
    shutdown: list[AppTask]


# A 'module:attribute' string (or the live object), validated into the object.
EntryPointString = Annotated[
    Any,
    AfterValidator(import_object),
]


__all__ = [
    "AccessTags",
    "AppTask",
    "EllipsisType",
    "JSON",
    "Scopes",
    "Query",
    "Filters",
    "TaskMap",
]
