from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, PrivateAttr


class TrustLevel(StrEnum):
    TRUSTED = "trusted"
    VERIFIED = "verified"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


class SourceType(StrEnum):
    SYSTEM_POLICY = "system_policy"
    USER_INSTRUCTION = "user_instruction"
    DOCUMENT = "document"
    WEB_CONTENT = "web_content"
    TOOL_OUTPUT = "tool_output"


class Decision(StrEnum):
    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


class ProvenanceSource(BaseModel):
    source_id: str = Field(min_length=1)
    source_type: SourceType
    trust_level: TrustLevel
    content: str = Field(min_length=1)
    parent_source_id: str | None = None
    _backend_attested: bool = PrivateAttr(default=False)

    @property
    def is_backend_trusted(self) -> bool:
        return self._backend_attested and self.trust_level in (
            TrustLevel.TRUSTED,
            TrustLevel.VERIFIED,
        )


def trusted_backend_source(
    source_id: str,
    source_type: SourceType,
    content: str,
    trust_level: TrustLevel = TrustLevel.TRUSTED,
    parent_source_id: str | None = None,
) -> ProvenanceSource:
    if source_type not in (SourceType.SYSTEM_POLICY, SourceType.USER_INSTRUCTION):
        raise ValueError("Only system and user instructions can be backend-trusted.")
    source = ProvenanceSource(
        source_id=source_id,
        source_type=source_type,
        trust_level=trust_level,
        content=content,
        parent_source_id=parent_source_id,
    )
    source._backend_attested = True
    return source


class ActionStep(BaseModel):
    action_type: str = Field(min_length=1)
    description: str = Field(min_length=1)
    target: str | None = None
    permissions: list[str] = Field(default_factory=list)
    provenance: list[ProvenanceSource] = Field(default_factory=list)
    provenance_refs: list[str] = Field(default_factory=list)


class ActionProposal(ActionStep):
    action_id: str = Field(min_length=1)
    sequence: list[ActionStep] = Field(default_factory=list)
    approval_request_id: str | None = None
    workflow_id: str | None = None


class Evidence(BaseModel):
    rule_id: str
    severity: Decision
    title: str
    detail: str
    source_ids: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    action_id: str
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    evidence: list[Evidence]
    recommended_next_step: str
    enforcement: str = "deterministic_policy"
    mode: str = "demo"


class ApprovalRequest(BaseModel):
    decision: Decision


class InterceptResponse(BaseModel):
    request_id: str
    action_id: str
    decision: Decision
    execution: str
    approval_required: bool
    risk_score: int = Field(ge=0, le=100)
    evidence: list[Evidence]
    recommended_next_step: str
    created_at: datetime


class AuditEvent(BaseModel):
    request_id: str
    action_id: str
    workflow_id: str | None = None
    decision: Decision
    status: str
    risk_score: int = Field(ge=0, le=100)
    evidence_count: int
    evidence: list[Evidence] = Field(default_factory=list)
    created_at: datetime
