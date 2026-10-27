from abc import abstractmethod
from collections.abc import Mapping
from typing import Any, ClassVar, Generic, Literal, Optional

from tiled.adapters.core import A, Adapter
from tiled.structures.container import ContainerStructure
from tiled.structures.core import StructureFamily


class ContainerAdapter(Adapter[ContainerStructure], Mapping[str, A], Generic[A]):
    structure_family: ClassVar[Literal[StructureFamily.container]] = (
        StructureFamily.container
    )

    @abstractmethod
    def read(self, fields: Optional[str] = None) -> Any:
        pass
