"""
Minimal in-house replacement for respx, for mocking outgoing HTTP calls.

Tiled code under test creates its own httpx2 clients internally, so a
MockTransport cannot be injected. Instead, ``MockRouter`` patches
``httpx2.HTTPTransport`` and ``httpx2.AsyncHTTPTransport`` so that every
request made through a real network transport is routed to a registered
``Route``. Requests matching no route raise ``UnmatchedRequestError`` so tests
never reach the network. In-process transports (e.g. the ASGI TestClient used
by ``Context.from_app``) are unaffected.
"""

import contextlib
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any, Optional, Union
from unittest.mock import patch
from urllib.parse import parse_qsl

import httpx2 as httpx

SideEffect = Union[
    BaseException,
    type[BaseException],
    Callable[[httpx.Request], httpx.Response],
    Iterable[Union[httpx.Response, BaseException]],
]


class UnmatchedRequestError(AssertionError):
    pass


@dataclass
class Call:
    request: httpx.Request
    response: Optional[httpx.Response]


class CallList(list):
    @property
    def last(self) -> Call:
        return self[-1]


class Route:
    def __init__(
        self,
        method: str,
        url: str,
        *,
        params: Optional[dict[str, Any]] = None,
        data: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        name: Optional[str] = None,
    ):
        self.method = method.upper()
        self.url = httpx.URL(url)
        self.params = params
        self.data = data
        self.headers = headers
        self.name = name
        self.return_value: Optional[httpx.Response] = None
        self.side_effect = None
        self.calls = CallList()

    @property
    def side_effect(self) -> Optional[SideEffect]:
        return self._side_effect

    @side_effect.setter
    def side_effect(self, value: Optional[SideEffect]) -> None:
        if value is not None and not callable(value):
            if not isinstance(value, BaseException):
                value = iter(value)
        self._side_effect = value

    @property
    def key(self) -> tuple:
        return (
            self.method,
            str(self.url),
            repr(self.params),
            repr(self.data),
            repr(self.headers),
        )

    @property
    def called(self) -> bool:
        return bool(self.calls)

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def mock(
        self,
        return_value: Optional[httpx.Response] = None,
        side_effect: Optional[SideEffect] = None,
    ) -> "Route":
        self.return_value = return_value
        self.side_effect = side_effect
        return self

    def matches(self, request: httpx.Request) -> bool:
        url = request.url
        if request.method != self.method:
            return False
        if (url.scheme, url.host, url.port, url.path or "/") != (
            self.url.scheme,
            self.url.host,
            self.url.port,
            self.url.path or "/",
        ):
            return False
        if self.url.query and url.params != self.url.params:
            return False
        if self.params is not None and any(
            url.params.get(k) != str(v) for k, v in self.params.items()
        ):
            return False
        if self.headers is not None and any(
            request.headers.get(k) != v for k, v in self.headers.items()
        ):
            return False
        if self.data is not None:
            form = dict(parse_qsl(request.content.decode()))
            if form != {k: str(v) for k, v in self.data.items()}:
                return False
        return True

    def respond(self, request: httpx.Request) -> httpx.Response:
        call = Call(request=request, response=None)
        self.calls.append(call)
        effect = self.side_effect
        if isinstance(effect, Iterator):
            effect = next(effect)
        if isinstance(effect, type) and issubclass(effect, BaseException):
            effect = effect("Mocked exception", request=request)
        if isinstance(effect, BaseException):
            if isinstance(effect, httpx.RequestError):
                effect.request = request
            raise effect
        if isinstance(effect, httpx.Response):
            response = effect
        elif callable(effect):
            response = effect(request)
        elif self.return_value is not None:
            response = self.return_value
        else:
            response = httpx.Response(httpx.codes.OK)
        # Copy so a response reused across calls is never shared between clients.
        response = httpx.Response(
            response.status_code,
            headers=response.headers,
            content=response.read(),
            request=request,
        )
        call.response = response
        return response


class MockRouter:
    def __init__(self) -> None:
        self.routes: list[Route] = []
        self.calls = CallList()

    def route(self, method: str, url: str, **kwargs: Any) -> Route:
        new = Route(method, url, **kwargs)
        for existing in self.routes:
            if existing.key == new.key:
                if new.name is not None:
                    existing.name = new.name
                return existing
        self.routes.append(new)
        return new

    def get(self, url: str, **kwargs: Any) -> Route:
        return self.route("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Route:
        return self.route("POST", url, **kwargs)

    def __getitem__(self, name: str) -> Route:
        for route in self.routes:
            if route.name == name:
                return route
        raise KeyError(name)

    def handle(self, request: httpx.Request) -> httpx.Response:
        for route in self.routes:
            if route.matches(request):
                try:
                    response = route.respond(request)
                finally:
                    self.calls.append(route.calls.last)
                return response
        raise UnmatchedRequestError(
            f"No mocked route matches {request.method} {request.url}"
        )

    @contextlib.contextmanager
    def patched(self) -> Iterator["MockRouter"]:
        router = self

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            request.read()
            return router.handle(request)

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            await request.aread()
            return router.handle(request)

        with (
            patch.object(httpx.HTTPTransport, "handle_request", handle_request),
            patch.object(
                httpx.AsyncHTTPTransport, "handle_async_request", handle_async_request
            ),
        ):
            yield self


@contextlib.contextmanager
def mock_http() -> Iterator[MockRouter]:
    "Route all outgoing httpx2 network requests to a fresh MockRouter."
    with MockRouter().patched() as router:
        yield router
