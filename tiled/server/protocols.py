from abc import ABC
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional, Protocol, runtime_checkable

from fastapi import Request

from ..type_aliases import AccessTags

if TYPE_CHECKING:
    import httpx2 as httpx


@dataclass
class UserSessionState:
    """Data transfer class to communicate custom session state information."""

    user_name: str
    state: Optional[dict] = None


class InternalAuthenticator(ABC):
    async def authenticate(
        self, username: str, password: str
    ) -> Optional[UserSessionState]:
        raise NotImplementedError


class ExternalAuthenticator(ABC):
    # Where to send the browser after authenticating, if anywhere.
    redirect_on_success: Optional[str] = None
    redirect_on_failure: Optional[str] = None

    async def authenticate(self, request: Request) -> Optional[UserSessionState]:
        raise NotImplementedError


@runtime_checkable
class OAuth2Authorizer(Protocol):
    """
    An external authenticator that sends users to an OAuth2 authorization
    endpoint, enabling the browser and device-code login routes.
    """

    @property
    def client_id(self) -> str: ...

    @property
    def authorization_endpoint(self) -> "httpx.URL": ...

    async def authenticate(self, request: Request) -> Optional[UserSessionState]: ...


@runtime_checkable
class MetadataReplaceable(Protocol):
    "A node whose metadata, specs, and access tags can be replaced."

    node: Any

    @property
    def access_tags(self) -> AccessTags: ...

    async def replace_metadata(
        self, metadata=None, specs=None, access_tags=None, *, drop_revision=False
    ) -> Any: ...
