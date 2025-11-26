
from pydantic import HttpUrl, TypeAdapter
from tiled.access_control.access_policies import ExternalPolicyDecisionPoint, ResultHolder
from typing import Any, Optional, TypedDict

from tiled.access_control.scopes import NO_SCOPES, PUBLIC_SCOPES
from tiled.adapters.protocols import BaseAdapter

from ..server.schemas import Principal, PrincipalType
from ..type_aliases import AccessBlob, AccessTags, Scopes


class AccessBlob(TypedDict):
    proposal: int
    visit: int


class DiamondOpenPolicyAgentAuthorizationPolicy(ExternalPolicyDecisionPoint):
    READ_SCOPES: set[str] = PUBLIC_SCOPES
    WRITE_SCOPES: set[str] = frozenset(
        (
            "write:metadata",
            "write:data",
            "create",
            "register",
        )
    )

    def __init__(
        self,
        authorization_provider: HttpUrl,
        token_audience: str,
        provider: Optional[str] = None,
        empty_access_blob_public: bool = False,
    ):
        self._token_audience = token_audience
        self._type_adapter = TypeAdapter(AccessBlob)

        super().__init__(
            authorization_provider,
            "session/write_to_beamline_visit",
            "session/user_sessions",  # TODO: New endpoint
            "token/claims",
            provider,
            empty_access_blob_public
        )

    def build_input(
            self,
            principal: Principal,
            authn_access_tags: Optional[AccessTags],
            authn_scopes: Scopes,
            access_blob: Optional[AccessBlob] = None
    ) -> str:
        if self._token_audience is None:
            raise ValueError("Provider not set, cannot validate token audience")
        if principal.type is not PrincipalType.external or principal.access_token is None:
            raise ValueError(
                "Access token not provided for external principal type"
            )
        blob = {} if access_blob is None else self._type_adapter.validate_json(access_blob["tags"][0])

        return str({
            **blob,
            "token": principal.access_token.get_secret_value(),
            "audience": self._token_audience,
        })

    async def allowed_scopes(
        self,
        node: BaseAdapter,
        principal: Principal,
        authn_access_tags: Optional[AccessTags],
        authn_scopes: Scopes,
    ) -> Scopes:
        scopes = await self._get_external_decision(
            self._node_scopes,
            self.build_input(principal, authn_access_tags, authn_scopes),
            ResultHolder[dict[str, Any]],
        )
        if scopes and scopes.result:
            return_scopes = set(self.READ_SCOPES)
            if "azp" in scopes.result and str(scopes.result["azp"]).endswith("-blueapi"):
                return_scopes |= self.WRITE_SCOPES
            return return_scopes
        return NO_SCOPES
