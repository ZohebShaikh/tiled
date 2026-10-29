import inspect
from abc import ABC
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Protocol,
    TypeGuard,
    runtime_checkable,
)

from fastapi import Request

from ..type_aliases import AccessTags

if TYPE_CHECKING:
    import httpx2 as httpx


@dataclass
class UserSessionState:
    """Data transfer class to communicate custom session state information."""

    user_name: str
    state: dict | None = None


class InternalAuthenticator(ABC):
    async def authenticate(
        self, username: str, password: str
    ) -> UserSessionState | None:
        raise NotImplementedError


class ExternalAuthenticator(ABC):
    # Where to send the browser after authenticating, if anywhere.
    redirect_on_success: str | None = None
    redirect_on_failure: str | None = None

    async def authenticate(self, request: Request) -> UserSessionState | None:
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

    async def authenticate(self, request: Request) -> UserSessionState | None: ...


def is_oauth2_authorizer(obj: object) -> TypeGuard[OAuth2Authorizer]:
    """
    Like isinstance(obj, OAuth2Authorizer), but never evaluates properties.

    On Python 3.11, isinstance() on a Protocol uses hasattr(), which would run
    OIDCAuthenticator's cached properties and fetch the IdP's configuration
    over the network at startup.
    """
    missing = object()
    return all(
        inspect.getattr_static(obj, name, missing) is not missing
        for name in ("client_id", "authorization_endpoint", "authenticate")
    )


@runtime_checkable
class MetadataReplaceable(Protocol):
    "A node whose metadata, specs, and access tags can be replaced."

    node: Any

    @property
    def access_tags(self) -> AccessTags: ...

    async def replace_metadata(
        self, metadata=None, specs=None, access_tags=None, *, drop_revision=False
    ) -> Any: ...
