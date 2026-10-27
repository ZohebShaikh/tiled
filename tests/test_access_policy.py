import uuid
from typing import Optional
from unittest.mock import MagicMock

import pytest
from httpx2 import Response
from pydantic import HttpUrl, SecretStr

from tiled.access_control.access_policies import ExternalPolicyDecisionPoint
from tiled.access_control.protocols import normalize_access_tags
from tiled.access_control.scopes import NO_SCOPES
from tiled.queries import AccessTagsFilter
from tiled.server.schemas import Principal, PrincipalType
from tiled.type_aliases import AccessTags, Scopes

from .http_mock import MockRouter


@pytest.fixture
def external_policy() -> ExternalPolicyDecisionPoint:
    class TestExternalPolicyDecisionPoint(ExternalPolicyDecisionPoint):
        def build_input(
            self,
            principal: Principal,
            authn_access_tags: Optional[AccessTags],
            authn_scopes: Scopes,
            access_tags: Optional[AccessTags] = None,
        ) -> str:
            return ""

    return TestExternalPolicyDecisionPoint(
        authorization_provider=HttpUrl("http://example.com"),
        create_node_endpoint="allow",
        allowed_tags_endpoint="tags",
        scopes_endpoint="scopes",
    )


@pytest.fixture
def principal() -> Principal:
    return Principal(
        type=PrincipalType.user,
        identities=[{"id": "alice", "provider": "dummy"}],
        uuid=uuid.uuid4(),
        access_token=SecretStr("token123"),
    )


@pytest.mark.asyncio
async def test_node_access_allowed(
    http_mock: MockRouter,
    external_policy: ExternalPolicyDecisionPoint,
    principal: Principal,
):
    http_mock.post(external_policy._create_node).mock(
        return_value=Response(200, json={"result": True})
    )
    assert await external_policy.init_node(
        principal=principal,
        authn_access_tags=normalize_access_tags(),
        authn_scopes=set([]),
        access_tags=normalize_access_tags(["beamline_x_user"]),
    ) == (True, normalize_access_tags(["beamline_x_user"]))


@pytest.mark.asyncio
async def test_node_access_denied(
    http_mock: MockRouter,
    external_policy: ExternalPolicyDecisionPoint,
    principal: Principal,
):
    http_mock.post(external_policy._create_node).mock(
        return_value=Response(200, json={"result": False})
    )
    assert await external_policy.init_node(
        principal=principal,
        authn_access_tags=normalize_access_tags(),
        authn_scopes=set([]),
        access_tags=normalize_access_tags(["beamline_x_user"]),
    ) == (False, normalize_access_tags(["beamline_x_user"]))


@pytest.mark.asyncio
async def test_node_modify_allowed(
    http_mock: MockRouter,
    external_policy: ExternalPolicyDecisionPoint,
    principal: Principal,
):
    node = MagicMock()
    node.access_tags = None
    http_mock.post(external_policy._create_node).mock(
        return_value=Response(200, json={"result": True})
    )
    assert await external_policy.modify_node(
        node=node,
        principal=principal,
        authn_access_tags=normalize_access_tags(),
        authn_scopes=set([]),
        access_tags=normalize_access_tags(["beamline_x_user"]),
    ) == (True, normalize_access_tags(["beamline_x_user"]))


@pytest.mark.asyncio
async def test_node_modify_denied(
    http_mock: MockRouter,
    external_policy: ExternalPolicyDecisionPoint,
    principal: Principal,
):
    node = MagicMock()
    node.access_tags = None
    http_mock.post(external_policy._create_node).mock(
        return_value=Response(200, json={"result": False})
    )
    assert await external_policy.modify_node(
        node=node,
        principal=principal,
        authn_access_tags=normalize_access_tags(),
        authn_scopes=set([]),
        access_tags=normalize_access_tags(["beamline_x_user"]),
    ) == (False, normalize_access_tags(["beamline_x_user"]))


@pytest.mark.asyncio
async def test_node_modify_denied_when_none_returned(
    http_mock: MockRouter,
    external_policy: ExternalPolicyDecisionPoint,
    principal: Principal,
):
    node = MagicMock()
    node.access_tags = None
    http_mock.post(external_policy._create_node).mock(return_value=Response(200))
    with pytest.raises(ValueError):
        await external_policy.modify_node(
            node=node,
            principal=principal,
            authn_access_tags=normalize_access_tags(),
            authn_scopes=set([]),
            access_tags=normalize_access_tags(["beamline_x_user"]),
        )


@pytest.mark.asyncio
async def test_node_modify_with_same_not_modified(
    external_policy: ExternalPolicyDecisionPoint, principal: Principal
):
    node = MagicMock()
    node.access_tags = normalize_access_tags(["beamline_x_user"])
    assert await external_policy.modify_node(
        node=node,
        principal=principal,
        authn_access_tags=normalize_access_tags(),
        authn_scopes=set([]),
        access_tags=normalize_access_tags(["beamline_x_user"]),
    ) == (False, normalize_access_tags(["beamline_x_user"]))


@pytest.mark.asyncio
async def test_access_filters(
    http_mock: MockRouter,
    external_policy: ExternalPolicyDecisionPoint,
    principal: Principal,
):
    output = {"result": ["beamline_x"]}
    http_mock.post(external_policy._user_tags).mock(
        return_value=Response(200, json=output)
    )

    filters = await external_policy.filters(
        node=MagicMock(),
        principal=principal,
        authn_access_tags=normalize_access_tags(),
        authn_scopes=set([]),
        scopes=set([]),
    )
    assert filters == [AccessTagsFilter(tags=["beamline_x"])]


@pytest.mark.asyncio
async def test_allowed_scopes(
    http_mock: MockRouter,
    external_policy: ExternalPolicyDecisionPoint,
    principal: Principal,
):
    http_mock.post(external_policy._node_scopes).mock(
        return_value=Response(200, json={"result": ["read:data", "write:data"]})
    )

    allowed_scopes = await external_policy.allowed_scopes(
        node=None,
        principal=principal,
        authn_access_tags=normalize_access_tags(),
        authn_scopes=set([]),
    )
    assert allowed_scopes == {"read:data", "write:data"}


@pytest.mark.asyncio
async def test_allowed_scopes_return_no_scopes_if_invalid_response(
    http_mock: MockRouter,
    external_policy: ExternalPolicyDecisionPoint,
    principal: Principal,
):
    http_mock.post(external_policy._node_scopes).mock(return_value=Response(200))

    allowed_scopes = await external_policy.allowed_scopes(
        node=None,
        principal=principal,
        authn_access_tags=normalize_access_tags(),
        authn_scopes=set([]),
    )
    assert allowed_scopes == NO_SCOPES


@pytest.mark.asyncio
async def test_allowed_scopes_return_no_scopes_if_validation_error(
    http_mock: MockRouter,
    external_policy: ExternalPolicyDecisionPoint,
    principal: Principal,
):
    http_mock.post(external_policy._node_scopes).mock(
        return_value=Response(200, json=True)
    )

    allowed_scopes = await external_policy.allowed_scopes(
        node=None,
        principal=principal,
        authn_access_tags=normalize_access_tags(),
        authn_scopes=set([]),
    )
    assert allowed_scopes == NO_SCOPES


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "allow,remote_allow", [(True, None), (False, None), (None, True), (None, False)]
)
async def test_empty_access_tags_public(
    http_mock: MockRouter,
    external_policy: ExternalPolicyDecisionPoint,
    principal: Principal,
    allow: Optional[bool],
    remote_allow: Optional[bool],
):
    external_policy._empty_access_tags_public = allow
    policy = external_policy
    if remote_allow is not None:
        route = http_mock.post(policy._create_node).mock(
            return_value=Response(200, json={"result": remote_allow})
        )
    else:
        route = None

    assert await policy.init_node(
        principal=principal,
        authn_access_tags=normalize_access_tags(),
        authn_scopes=set([]),
        access_tags=None,
    ) == (allow if allow is not None else remote_allow, normalize_access_tags())

    if route:
        assert route.call_count == 1
