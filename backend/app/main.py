from datetime import datetime, timezone
from secrets import token_urlsafe
from threading import Lock
from uuid import uuid4

import os
import re
from typing import Annotated
from fastapi import Cookie, FastAPI, File, Header, UploadFile, Response
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .models import (
    ActionProposal,
    AnalysisResult,
    ApprovalRequest,
    AuditEvent,
    Decision,
    DocumentApproval,
    DocumentAuditEvent,
    DocumentClassification,
    DocumentFinding,
    DocumentMonitorItem,
    DocumentProvenance,
    DocumentScanResult,
    InterceptResponse,
    ProvenanceSource,
    SourceType,
    TrustLevel,
)
from .ai_security_analyzer import (
    AISecurityAnalysisError,
    analyze_document_text,
    analyze_security_context,
)
from .document_gateway import create_document_provenance, extract_text, scan_text
from .document_store import DocumentStore
from .policy_engine import analyze_proposal
from .auth_store import AgentConnectionRecord, AuthStore, UserRecord
from pydantic import BaseModel, Field

app = FastAPI(
    title="TrustFirewall API",
    version="0.1.0",
    description="Deterministic provenance-aware security analysis for simulated agent actions.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
    allow_credentials=True,
)
_audit_events: dict[str, AuditEvent] = {}
_audit_owners: dict[str, str] = {}
_workflow_history: dict[str, list[ActionProposal]] = {}
_document_store = DocumentStore()
_auth_store = AuthStore(_document_store.path)
_audit_lock = Lock()


class RegisterRequest(BaseModel):
    full_name: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=200)


class LoginRequest(BaseModel):
    email: str
    password: str


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=12, max_length=200)
    confirm_password: str = Field(min_length=12, max_length=200)


class ProfileUpdate(BaseModel):
    full_name: str = Field(min_length=1, max_length=120)
    profile_image_url: str | None = Field(default=None, max_length=1000)


class ConnectionRequest(BaseModel):
    provider: str = Field(pattern=r"^(chatgpt|claude|gemini|custom)$")
    status: str = Field(default="selected", pattern=r"^(not_selected|selected|connecting|connected|failed|disconnected|configuration_required)$")


def _public_user(user: UserRecord) -> dict[str, object]:
    return user.model_dump(mode="json")


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        "trustfirewall_session",
        token,
        httponly=True,
        secure=os.getenv("TRUSTFIREWALL_COOKIE_SECURE", "false").lower() == "true",
        samesite="lax",
        max_age=604800,
        path="/",
    )


def _authenticated_user(session: str | None) -> UserRecord:
    if not session:
        raise HTTPException(status_code=401, detail="Authentication is required.")
    user = _auth_store.get_session_user(session)
    if user is None:
        raise HTTPException(status_code=401, detail="Your session has expired.")
    return user


def _validate_email(email: str) -> str:
    normalized = email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    return normalized


@app.post("/api/auth/register", status_code=201)
def register(request: RegisterRequest, response: Response) -> dict[str, object]:
    email = _validate_email(request.email)
    try:
        user = _auth_store.create_user(request.full_name.strip(), email, request.password)
    except Exception as error:
        if "UNIQUE constraint failed" in str(error):
            raise HTTPException(status_code=409, detail="An account with that email already exists.") from error
        raise
    _set_session_cookie(response, _auth_store.create_session(user.user_id))
    return {"user": _public_user(user)}


@app.post("/api/auth/login")
def login(request: LoginRequest, response: Response) -> dict[str, object]:
    user = _auth_store.authenticate(_validate_email(request.email), request.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    _set_session_cookie(response, _auth_store.create_session(user.user_id))
    return {"user": _public_user(user)}


@app.post("/api/auth/logout", status_code=204)
def logout(response: Response, session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None) -> None:
    if session:
        _auth_store.delete_session(session)
    response.delete_cookie("trustfirewall_session")


@app.get("/api/auth/me")
def auth_me(session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None) -> dict[str, object]:
    return {"user": _public_user(_authenticated_user(session))}


@app.get("/api/users/me")
def get_profile(session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None) -> dict[str, object]:
    return {"user": _public_user(_authenticated_user(session))}


@app.patch("/api/users/me")
def update_profile(request: ProfileUpdate, session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None) -> dict[str, object]:
    user = _authenticated_user(session)
    return {"user": _public_user(_auth_store.update_user(user.user_id, request.full_name.strip(), request.profile_image_url))}


@app.post("/api/auth/change-password")
def change_password(request: PasswordChangeRequest, session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None) -> dict[str, str]:
    user = _authenticated_user(session)
    if request.new_password != request.confirm_password:
        raise HTTPException(status_code=422, detail="New passwords do not match.")
    stored = _auth_store.get_password_hash(user.user_id)
    if not stored or not _auth_store.verify_password(request.current_password, stored):
        raise HTTPException(status_code=403, detail="Current password is incorrect.")
    _auth_store.change_password(user.user_id, request.new_password)
    _auth_store.revoke_other_sessions(user.user_id, session)
    return {"status": "password_changed"}


@app.get("/api/agents")
def agent_catalog() -> list[dict[str, object]]:
    return [
        {"provider": "chatgpt", "display_name": "ChatGPT", "description": "Requires a configured integration.", "supported": False, "configuration_required": True},
        {"provider": "claude", "display_name": "Claude", "description": "Requires a configured integration.", "supported": False, "configuration_required": True},
        {"provider": "gemini", "display_name": "Google Gemini", "description": "Requires a configured integration.", "supported": False, "configuration_required": True},
        {"provider": "custom", "display_name": "Custom agent", "description": "Use the TrustFirewall MCP proxy.", "supported": True, "configuration_required": False},
    ]


@app.get("/api/agents/connections", response_model=list[AgentConnectionRecord])
def agent_connections(session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None) -> list[AgentConnectionRecord]:
    return _auth_store.list_connections(_authenticated_user(session).user_id)


@app.post("/api/agents/connections", response_model=AgentConnectionRecord)
def create_agent_connection(request: ConnectionRequest, session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None) -> AgentConnectionRecord:
    status_value = request.status
    if request.provider != "custom" and status_value in {"selected", "connecting", "connected"}:
        status_value = "configuration_required"
    return _auth_store.upsert_connection(_authenticated_user(session).user_id, request.provider, status_value)


@app.patch("/api/agents/connections/{connection_id}", response_model=AgentConnectionRecord)
def update_agent_connection(connection_id: str, request: ConnectionRequest, session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None) -> AgentConnectionRecord:
    user = _authenticated_user(session)
    current = next((item for item in _auth_store.list_connections(user.user_id) if item.connection_id == connection_id), None)
    if current is None:
        raise HTTPException(status_code=404, detail="Connection was not found.")
    status_value = request.status
    if current.provider != "custom" and status_value in {"selected", "connecting", "connected"}:
        status_value = "configuration_required"
    return _auth_store.upsert_connection(user.user_id, current.provider, status_value)


@app.delete("/api/agents/connections/{connection_id}", status_code=204)
def delete_agent_connection(connection_id: str, session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None) -> None:
    if not _auth_store.delete_connection(_authenticated_user(session).user_id, connection_id):
        raise HTTPException(status_code=404, detail="Connection was not found.")




@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "demo"}


def _record_document_event(
    document: DocumentScanResult,
    event_type: str,
    detail: str,
) -> None:
    _document_store.add_audit(
        DocumentAuditEvent(
            event_id=str(uuid4()),
            document_id=document.document_id,
            filename=document.filename,
            event_type=event_type,
            classification=document.classification,
            detail=detail,
            created_at=datetime.now(timezone.utc),
        )
    )


def _analyze_with_context(
    proposal: ActionProposal,
    history: tuple[ActionProposal, ...],
) -> AnalysisResult:
    proposal = _attach_document_sources(proposal)
    try:
        ai_analysis = analyze_security_context(
            proposal,
            user_task=proposal.user_task or "",
            document_provenance=proposal.document_provenance,
            document_findings=proposal.document_findings,
        )
    except AISecurityAnalysisError:
        return analyze_proposal(proposal, history, ai_status="unavailable")
    return analyze_proposal(
        proposal,
        history,
        ai_analysis=ai_analysis,
        ai_status="completed",
    )


def _attach_document_sources(proposal: ActionProposal) -> ActionProposal:
    """Resolve backend document metadata into untrusted policy sources."""
    existing_ids = {source.source_id for source in proposal.provenance}
    document_sources = []
    for provenance in proposal.document_provenance:
        if provenance.source_id in existing_ids:
            continue
        finding_text = " ".join(
            finding.detected_text
            for finding in proposal.document_findings
            if finding.source_id in {None, provenance.source_id}
        )
        document_sources.append(
            ProvenanceSource(
                source_id=provenance.source_id,
                source_type=SourceType.DOCUMENT,
                trust_level=TrustLevel.UNTRUSTED,
                content=finding_text or f"Document {provenance.filename}.",
            )
        )
    if not document_sources:
        return proposal
    return proposal.model_copy(
        update={"provenance": [*proposal.provenance, *document_sources]}
    )


@app.post("/api/documents/scan", response_model=list[DocumentScanResult])
async def scan_documents(
    files: list[UploadFile] = File(...),
    session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None,
) -> list[DocumentScanResult]:
    user = _auth_store.get_session_user(session) if session else None
    results: list[DocumentScanResult] = []
    for uploaded_file in files:
        document_id = str(uuid4())
        owner_token = token_urlsafe(32)
        filename = uploaded_file.filename or "unnamed-document"
        content = b""
        provenance = create_document_provenance(
            document_id,
            filename,
            content,
            "application/octet-stream",
        )
        try:
            content = await uploaded_file.read()
            provenance = create_document_provenance(
                document_id,
                filename,
                content,
                "application/octet-stream",
            )
            extracted = extract_text(filename, content)
            provenance = create_document_provenance(
                document_id,
                filename,
                content,
                extracted.content_type,
            )
            classification, findings = scan_text(
                filename,
                extracted.text,
                source_id=provenance.source_id,
                content_sha256=provenance.content_sha256,
            )
            ai_findings = analyze_document_text(filename, extracted.text)
            findings.extend(
                DocumentFinding(
                    filename=filename,
                    line_number=item.line_number,
                    detected_text=item.detected_text,
                    severity=DocumentClassification(item.severity.value),
                    explanation=item.explanation,
                    rule_id="AI-ADVISORY",
                    evidence=item.evidence,
                    source_id=provenance.source_id,
                    content_sha256=provenance.content_sha256,
                )
                for item in ai_findings
            )
            status = (
                "released"
                if classification == DocumentClassification.SAFE
                else "pending_approval"
                if classification == DocumentClassification.SUSPICIOUS
                else "blocked"
            )
            result = DocumentScanResult(
                document_id=document_id,
                owner_token=owner_token,
                filename=filename,
                classification=classification,
                status=status,
                findings=findings,
                provenance=provenance,
                extracted_line_count=len(extracted.text.splitlines()),
                created_at=datetime.now(timezone.utc),
            )
            _document_store.save_document(result, content, extracted.content_type, owner_token, user.user_id if user else None)
            _record_document_event(
                result,
                "upload",
                f"Document uploaded with SHA-256 {provenance.content_sha256}.",
            )
            _record_document_event(result, "scan", f"Document scanned as {classification}.")
            if classification == DocumentClassification.MALICIOUS:
                rule_ids = ", ".join(sorted({finding.rule_id for finding in findings}))
                _record_document_event(
                    result,
                    "malicious_finding",
                    f"Malicious findings detected by rules: {rule_ids}.",
                )
        except Exception as error:
            result = DocumentScanResult(
                document_id=document_id,
                owner_token=owner_token,
                filename=filename,
                classification=DocumentClassification.MALICIOUS,
                status="blocked",
                findings=[],
                provenance=provenance,
                extracted_line_count=0,
                created_at=datetime.now(timezone.utc),
            )
            _document_store.save_document(
                result,
                content,
                provenance.content_type,
                owner_token,
                user.user_id if user else None,
            )
            _record_document_event(
                result,
                "scan_failed",
                f"Document denied because extraction or scanning failed: {error}",
            )
        results.append(result)
    return results


@app.post("/api/documents/{document_id}/approval", response_model=DocumentScanResult)
def approve_document(
    document_id: str,
    request: DocumentApproval,
    session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None,
) -> DocumentScanResult:
    stored = _document_store.get_document(document_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Document was not found.")
    _, _, document, owner_token = stored
    owner_user_id = _document_store.get_document_owner(document_id)
    if owner_user_id:
        user = _authenticated_user(session)
        if user.user_id != owner_user_id:
            raise HTTPException(status_code=404, detail="Document was not found.")
    if request.owner_token != owner_token:
        raise HTTPException(status_code=403, detail="Document ownership could not be verified.")
    if request.decision not in {"approve", "override", "deny"}:
        raise HTTPException(status_code=422, detail="Decision must be approve, override, or deny.")
    if request.decision == "deny":
        updated = document.model_copy(update={"status": "denied"})
    elif document.classification == DocumentClassification.SUSPICIOUS and request.decision == "approve":
        updated = document.model_copy(update={"status": "released"})
    elif document.classification == DocumentClassification.MALICIOUS and request.decision == "override":
        if not _document_store.add_confirmation(document_id, request.approver_id):
            raise HTTPException(status_code=409, detail="A second override must come from a different approver.")
        if _document_store.confirmation_count(document_id) < 2:
            updated = document.model_copy(update={"status": "pending_override"})
        else:
            updated = document.model_copy(update={"status": "released"})
    else:
        raise HTTPException(status_code=409, detail="This approval does not match the document classification.")
    _document_store.update_document(updated)
    _record_document_event(updated, request.decision, f"Human decision recorded: {request.decision}.")
    return updated


@app.get("/api/documents/{document_id}/release")
def release_document(
    document_id: str,
    authorization: str | None = Header(default=None),
    session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None,
) -> dict[str, str | bytes]:
    stored = _document_store.get_document(document_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Document was not found.")
    content, content_type, document, owner_token = stored
    owner_user_id = _document_store.get_document_owner(document_id)
    if owner_user_id:
        user = _authenticated_user(session)
        if user.user_id != owner_user_id:
            raise HTTPException(status_code=404, detail="Document was not found.")
    if authorization != f"Bearer {owner_token}":
        raise HTTPException(status_code=403, detail="Document ownership could not be verified.")
    if document.status != "released":
        raise HTTPException(status_code=403, detail="Document is not released by TrustFirewall.")
    _record_document_event(document, "release", "Original document released through the TrustFirewall gateway.")
    from fastapi.responses import Response

    return Response(content=content, media_type=content_type, headers={"Content-Disposition": f'attachment; filename="{document.filename}"'})


@app.get("/api/document-audit", response_model=list[DocumentAuditEvent])
def document_audit_history(session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None) -> list[DocumentAuditEvent]:
    with _audit_lock:
        user = _auth_store.get_session_user(session) if session else None
        return _document_store.audit_history(user.user_id if user else None)


@app.get("/api/documents/monitoring", response_model=list[DocumentMonitorItem])
def document_monitoring(session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None) -> list[DocumentMonitorItem]:
    return _document_store.list_documents(_authenticated_user(session).user_id)


@app.post("/api/analyze", response_model=AnalysisResult)
def analyze_action(proposal: ActionProposal) -> AnalysisResult:
    with _audit_lock:
        history = tuple(_workflow_history.get(_workflow_key(proposal), ()))
    return _analyze_with_context(proposal, history)


def _workflow_key(proposal: ActionProposal) -> str:
    # Unidentified requests must not share state with one another.
    return proposal.workflow_id or f"anonymous:{proposal.action_id}"


def _intercept_response(
    request_id: str,
    proposal: ActionProposal,
    analysis: AnalysisResult,
    status: str,
    execution: str,
    approval_required: bool,
    created_at: datetime,
) -> InterceptResponse:
    return InterceptResponse(
        request_id=request_id,
        action_id=proposal.action_id,
        decision=analysis.decision,
        execution=execution,
        approval_required=approval_required,
        risk_score=analysis.risk_score,
        evidence=analysis.evidence,
        recommended_next_step=analysis.recommended_next_step,
        created_at=created_at,
        threat_categories=analysis.threat_categories,
        source_ids=analysis.source_ids,
        mode=analysis.mode,
        ai_status=analysis.ai_status,
    )


@app.post("/api/intercept", response_model=InterceptResponse)
def intercept_action(
    proposal: ActionProposal,
    session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None,
) -> InterceptResponse:
    if proposal.approval_request_id:
        with _audit_lock:
            previous = _audit_events.get(proposal.approval_request_id)
            history = tuple(_workflow_history.get(_workflow_key(proposal), ()))
        if previous is None:
            raise HTTPException(status_code=404, detail="Approval request was not found.")
        if previous.status == "approved":
            if previous.action_id != proposal.action_id:
                raise HTTPException(
                    status_code=409,
                    detail="Approval request does not match this action.",
                )
            analysis = _analyze_with_context(proposal, history)
            if analysis.decision == Decision.BLOCK:
                raise HTTPException(
                    status_code=409,
                    detail="The deterministic policy still blocks this action.",
                )
            approved_analysis = analysis.model_copy(update={"decision": Decision.ALLOW})
            now = datetime.now(timezone.utc)
            return _intercept_response(
                previous.request_id,
                proposal,
                approved_analysis,
                "approved",
                "allowed",
                False,
                now,
            )
        raise HTTPException(status_code=409, detail="Approval request is not approved.")

    workflow_key = _workflow_key(proposal)
    with _audit_lock:
        history = tuple(_workflow_history.get(workflow_key, ()))
    analysis = _analyze_with_context(proposal, history)
    request_id = str(uuid4())
    created_at = datetime.now(timezone.utc)
    if analysis.decision == Decision.ALLOW:
        status, execution, approval_required = "allowed", "allowed", False
    elif analysis.decision == Decision.FLAG:
        status, execution, approval_required = "pending_approval", "blocked", True
    else:
        status, execution, approval_required = "blocked", "blocked", False

    event = AuditEvent(
        request_id=request_id,
        action_id=proposal.action_id,
        workflow_id=proposal.workflow_id,
        decision=analysis.decision,
        status=status,
        risk_score=analysis.risk_score,
        evidence_count=len(analysis.evidence),
        evidence=analysis.evidence,
        created_at=created_at,
    )
    with _audit_lock:
        _audit_events[request_id] = event
        if session:
            owner = _auth_store.get_session_user(session)
            if owner:
                _audit_owners[request_id] = owner.user_id
        _workflow_history.setdefault(workflow_key, []).append(proposal)
    return _intercept_response(
        request_id,
        proposal,
        analysis,
        status,
        execution,
        approval_required,
        created_at,
    )


@app.get("/api/audit", response_model=list[AuditEvent | DocumentAuditEvent])
def audit_history(session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None) -> list[AuditEvent | DocumentAuditEvent]:
    user = _auth_store.get_session_user(session) if session else None
    with _audit_lock:
        events = list(_audit_events.values()) if user is None else [
            event for request_id, event in _audit_events.items()
            if _audit_owners.get(request_id) == user.user_id
        ]
        events.extend(_document_store.audit_history(user.user_id if user else None))
        return sorted(events, key=lambda event: event.created_at, reverse=True)


@app.post("/api/audit/{request_id}/approval", response_model=AuditEvent)
def approve_intercept(
    request_id: str,
    request: ApprovalRequest,
    session: Annotated[str | None, Cookie(alias="trustfirewall_session")] = None,
) -> AuditEvent:
    with _audit_lock:
        event = _audit_events.get(request_id)
        if event is None:
            raise HTTPException(status_code=404, detail="Approval request was not found.")
        owner_id = _audit_owners.get(request_id)
        if owner_id:
            user = _authenticated_user(session)
            if owner_id != user.user_id:
                raise HTTPException(status_code=404, detail="Approval request was not found.")
        if event.decision != Decision.FLAG:
            raise HTTPException(
                status_code=409,
                detail="Only flagged actions can be approved or denied.",
            )
        status = "approved" if request.decision == Decision.ALLOW else "denied"
        updated = event.model_copy(update={"status": status})
        _audit_events[request_id] = updated
        return updated
