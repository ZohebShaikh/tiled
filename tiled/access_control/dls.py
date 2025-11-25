
import os
from pydantic import HttpUrl, Secret
from tiled.access_control.access_policies import ExternalPolicyDecisionPoint, ResultHolder
from typing import Any, Optional

from tiled.access_control.scopes import NO_SCOPES, PUBLIC_SCOPES
from tiled.adapters.protocols import BaseAdapter

from ..server.schemas import Principal, PrincipalType
from ..type_aliases import AccessBlob, AccessTags, Scopes


class OpenPolicyAgentVerified:
    result: tuple[dict[str, Any], dict[str, Any]]

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
        self._blueapi_secret_key: Secret[str] = Secret(os.environ['BLUEAPI_SECRET_KEY']),

        super().__init__(
            authorization_provider,
            "diamond.policy.session.write_to_beamline_visit",
            "diamond.policy.session.user_sessions",  # TODO: New endpoint
            "diamond.policy.token.verified",
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
        return str({
            **access_blob,
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
            self.build_input(principal, authn_access_tags, authn_scopes, getattr(node, "access_blob", None)),
            ResultHolder[bool],
        )
        if scopes and scopes.result:
            return_scopes = set(self.READ_SCOPES)
            if "azp" in scopes.result[1] and str(scopes.result[1]["azp"]).endswith("-blueapi"):
                return_scopes |= self.WRITE_SCOPES
            return return_scopes
        return NO_SCOPES
