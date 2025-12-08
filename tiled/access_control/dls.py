import json
import logging
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl, TypeAdapter

from tiled.access_control.access_policies import ExternalPolicyDecisionPoint

from ..server.schemas import Principal, PrincipalType
from ..type_aliases import AccessBlob, AccessTags, Scopes

logger = logging.getLogger(__name__)


class DiamondAccessBlob(BaseModel):
    proposal: int = Field(validation_alias="proposal_number")
    visit: int = Field(validation_alias="visit_number")
    beamline: str


class DiamondOpenPolicyAgentAuthorizationPolicy(ExternalPolicyDecisionPoint):
    def __init__(
        self,
        authorization_provider: HttpUrl,
        token_audience: str,
        provider: Optional[str] = None,
    ):
        self._token_audience = token_audience
        self._type_adapter = TypeAdapter(DiamondAccessBlob)

        super().__init__(
            authorization_provider,
            "session/write_to_beamline_visit",
            "session/user_sessions",
            "tiled/scopes",
            provider,
            empty_access_blob_public=True,
            empty_tag_list_include_all=True,
            no_tag_list_exclude_all=True,
        )

    def build_input(
        self,
        principal: Principal,
        authn_access_tags: Optional[AccessTags],
        authn_scopes: Scopes,
        access_blob: Optional[AccessBlob] = None,
    ) -> str:
        _input = {"audience": self._token_audience}

        if (
            principal.type is PrincipalType.external
            and principal.access_token is not None
        ):
            _input["token"] = principal.access_token.get_secret_value()

        if (
            access_blob is not None
            and "tags" in access_blob
            and len(access_blob["tags"] > 0)
        ):
            blob = self._type_adapter.validate_json(access_blob["tags"][0])
            _input.update(blob.model_dump())

        return json.dumps({"input": _input})
