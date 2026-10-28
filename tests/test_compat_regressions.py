"""
Behaviors that must survive typing refactors. Each test covers a public
contract that was briefly broken while tightening types.
"""

import httpx2 as httpx
from fastapi.testclient import TestClient

from tiled.adapters.mapping import MapAdapter
from tiled.server.app import build_app_from_config
from tiled.server.protocols import ExternalAuthenticator

tree = MapAdapter({})


class CustomOAuth2Authenticator(ExternalAuthenticator):
    "An external authenticator that is not an OIDCAuthenticator subclass."

    client_id = "custom-client"
    authorization_endpoint = httpx.URL("https://idp.example.com/authorize")

    async def authenticate(self, request):
        return None


def test_authorize_route_for_non_oidc_external_authenticator(tmp_path):
    config = {
        "authentication": {
            "secret_keys": ["SECRET"],
            "providers": [
                {
                    "provider": "custom",
                    "authenticator": f"{__name__}:CustomOAuth2Authenticator",
                }
            ],
        },
        "database": {
            "uri": f"sqlite:///{tmp_path / 'auth.db'}",
            "init_if_not_exists": True,
        },
        "trees": [{"tree": f"{__name__}:tree", "path": "/"}],
    }
    with TestClient(build_app_from_config(config)) as client:
        response = client.get(
            "/api/v1/auth/provider/custom/authorize", follow_redirects=False
        )
    assert response.is_redirect
    location = response.headers["location"]
    assert location.startswith("https://idp.example.com/authorize")
    assert "client_id=custom-client" in location


def test_iterviews_accept_length_callable():
    "The original KeysView(get_length, keys_slice) signature keeps working."
    from tiled.iterviews import ItemsView, KeysView, ValuesView

    data = {"a": 1, "b": 2, "c": 3}
    keys = list(data)

    def keys_slice(start, stop, direction, page_size):
        selected = keys[start:stop] if direction > 0 else keys[::-1][start:stop]
        return iter(selected)

    def items_slice(start, stop, direction, page_size):
        return ((k, data[k]) for k in keys_slice(start, stop, direction, page_size))

    for view in (
        KeysView(lambda: len(data), keys_slice),
        ItemsView(lambda: len(data), items_slice),
        ValuesView(lambda: len(data), items_slice),
    ):
        assert len(view) == 3
        assert bool(view)
    assert KeysView(lambda: 3, keys_slice)[0] == "a"
    assert "b" in KeysView(lambda: 3, keys_slice)
    assert ("b", 2) in ItemsView(lambda: 3, items_slice)
    assert 2 in ValuesView(lambda: 3, items_slice)
    assert list(KeysView(lambda: 3, keys_slice).page_size(1)) == keys


def test_composite_delete_contents_positional_external_only():
    import inspect

    from tiled.client.composite import CompositeClient

    params = list(inspect.signature(CompositeClient.delete_contents).parameters)
    assert params[:3] == ["self", "keys", "external_only"]


def test_csv_tz_aware_column_stays_datetime64(tmp_path):
    "Columns use .values; .to_numpy() would turn tz-aware datetimes into objects."
    import numpy

    from tiled.adapters.csv import CSVAdapter
    from tiled.utils import ensure_uri

    path = tmp_path / "table.csv"
    path.write_text("t\n2024-01-01T00:00:00+00:00\n2024-01-02T00:00:00+00:00\n")
    adapter = CSVAdapter.from_uris(ensure_uri(path), parse_dates=["t"])
    assert adapter["t"].structure().data_type.to_numpy_dtype().kind == "M"
    assert adapter["t"].read().dtype != numpy.dtype(object)


def test_retry_indicator_reset_ignores_widget_close_errors():
    "reset() runs in finally blocks; a failing widget close must not mask errors."
    from tiled.client.utils import StandaloneRetryIndicator

    class BrokenLabel:
        def close(self):
            raise RuntimeError("comm already closed")

    indicator = StandaloneRetryIndicator()
    indicator._showing = True
    indicator._label = BrokenLabel()
    indicator.reset()
    assert indicator._label is None


def test_router_dispatches_on_capability_not_catalog_class():
    "Any adapter that has the method may serve the write route, as with hasattr."
    import numpy

    from tiled.adapters.array import ArrayAdapter
    from tiled.client import Context, from_context
    from tiled.server.app import build_app

    deleted = []

    class DeletableArrayAdapter(ArrayAdapter):
        async def delete(self, recursive=False, external_only=True):
            deleted.append((recursive, external_only))

    node = MapAdapter({"x": DeletableArrayAdapter.from_array(numpy.zeros(3))})
    with Context.from_app(build_app(node)) as context:
        from_context(context).delete_contents("x", external_only=False)
    assert deleted == [(False, False)]


def test_malformed_spec_in_json_patch_is_422(tmp_path):
    import pytest

    from tiled.catalog import in_memory
    from tiled.client import Context, from_context
    from tiled.client.utils import ClientError
    from tiled.server.app import build_app

    catalog = in_memory(writable_storage=str(tmp_path))
    with Context.from_app(build_app(catalog)) as context:
        container = from_context(context).create_container("c")
        with pytest.raises(ClientError) as info:
            container.patch_metadata(
                specs_patch=[{"op": "add", "path": "/-", "value": {"nmae": "x"}}]
            )
    assert info.value.response.status_code == 422


def test_identity_provider_input_reprompts_on_bad_choice(monkeypatch):
    from tiled.client.context import identity_provider_input

    class Provider:
        def __init__(self, provider):
            self.provider = provider

    providers = [Provider("a"), Provider("b")]
    answers = iter(["abc", "0", "3", "-1", "2"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert identity_provider_input(providers).provider == "b"


def test_keys_pagination_does_not_require_items_pagination():
    "Matches the old separate hasattr(keys_page) / hasattr(items_page) checks."
    from tiled.server.core import ItemsPaginatedAdapter, KeysPaginatedAdapter

    class KeysOnly:
        async def cursor_for_offset(self, offset):
            return None

        async def keys_page(self, cursor=None, limit=None):
            return [], None

        async def keys_range(self, offset=0, limit=None):
            return []

    assert isinstance(KeysOnly(), KeysPaginatedAdapter)
    assert not isinstance(KeysOnly(), ItemsPaginatedAdapter)
