from abc import ABC
from dataclasses import dataclass

from fastapi import Request
from pydantic import BaseModel, ConfigDict


@dataclass
class UserSessionState:
    """Data transfer class to communicate custom session state information."""

    user_name: str
    state: dict = None


class Authenticator(BaseModel, ABC):
    """Base for authenticators, whose configuration is validated by pydantic.

    Subclasses declare their configuration as fields; unknown arguments are
    rejected so that typos in a server configuration file fail loudly.
    """

    model_config = ConfigDict(extra="forbid")

    confirmation_message: str = ""
    "May be displayed by client after successful login."


class InternalAuthenticator(Authenticator):
    def authenticate(self, username: str, password: str) -> UserSessionState | None:
        raise NotImplementedError


class ExternalAuthenticator(Authenticator):
    def authenticate(self, request: Request) -> UserSessionState | None:
        raise NotImplementedError
