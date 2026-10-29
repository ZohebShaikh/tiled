import pytest
from starlette.testclient import TestClient

from tiled.adapters.mapping import MapAdapter
from tiled.server.app import CSRF_QUERY_PARAMETER, build_app
from tiled.server.utils import API_KEY_COOKIE_NAME, CSRF_COOKIE_NAME


@pytest.mark.parametrize("token, expected_status", [("good", None), ("bad", 403)])
def test_csrf_token_from_query_parameter(token, expected_status):
    "The double-submit CSRF token may be sent as a query parameter."
    app = build_app(MapAdapter({}))
    with TestClient(app) as client:
        client.cookies.set(API_KEY_COOKIE_NAME, "secret")
        client.cookies.set(CSRF_COOKIE_NAME, "good")
        response = client.post(f"/api/v1/metadata/?{CSRF_QUERY_PARAMETER}={token}")
    if expected_status is None:
        # Past the CSRF check; whatever the route does next is not under test.
        assert response.status_code not in (403, 500)
    else:
        assert response.status_code == expected_status
