from abc import ABC
from dataclasses import dataclass
from typing import Optional

from fastapi import Request


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
