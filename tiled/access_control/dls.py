
from tiled.access_control.access_policies import ExternalPolicyDecisionPoint
from typing import Optional

from ..server.schemas import Principal, PrincipalType
from ..type_aliases import AccessBlob, AccessTags, Scopes

class DiamondOpenPolicyAgentAuthorizationPolicy(ExternalPolicyDecisionPoint):
    def build_input(
            self,
            principal: Principal,
            authn_access_tags: Optional[AccessTags],
            authn_scopes: Scopes,
            access_blob: Optional[AccessBlob] = None
    ) -> str:
        if self._provider is None:
            raise ValueError("Provider not set, cannot validate token audience")
        if principal.type is not PrincipalType.external or principal.access_token is None:
            raise ValueError(
                "Access token not provided for external principal type"
            )
        return str({
            **access_blob,
            "token": principal.access_token.get_secret_value(),
            "audience": self._provider,
        })
