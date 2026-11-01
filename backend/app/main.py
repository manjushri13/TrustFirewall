from datetime import datetime, timezone
from secrets import token_urlsafe
from threading import Lock
from uuid import uuid4

from fastapi import FastAPI, File, Header, UploadFile
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
    DocumentScanResult,
    InterceptResponse,
)
from .document_gateway import extract_text, scan_text
from .document_store import DocumentStore
from .ai_security_analyzer import analyze_document_text
from .policy_engine import analyze_proposal

app = FastAPI(
    title="TrustFirewall API",
    version="0.1.0",
    description="Deterministic provenance-aware security analysis for simulated agent actions.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
_audit_events: dict[str, AuditEvent] = {}
_workflow_history: dict[str, list[ActionProposal]] = {}
_document_store = DocumentStore()
_audit_lock = Lock()


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


@app.post("/api/documents/scan", response_model=list[DocumentScanResult])
async def scan_documents(files: list[UploadFile] = File(...)) -> list[DocumentScanResult]:
    results: list[DocumentScanResult] = []
    for uploaded_file in files:
        document_id = str(uuid4())
        owner_token = token_urlsafe(32)
        filename = uploaded_file.filename or "unnamed-document"
        try:
            content = await uploaded_file.read()
            extracted = extract_text(filename, content)
            classification, findings = scan_text(filename, extracted.text)
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
                extracted_line_count=len(extracted.text.splitlines()),
                created_at=datetime.now(timezone.utc),
            )
            _document_store.save_document(result, content, extracted.content_type, owner_token)
            _record_document_event(result, "scan", f"Document scanned as {classification}.")
        except Exception as error:
            result = DocumentScanResult(
                document_id=document_id,
                owner_token=owner_token,
                filename=filename,
                classification=DocumentClassification.MALICIOUS,
                status="blocked",
                findings=[],
                extracted_line_count=0,
                created_at=datetime.now(timezone.utc),
            )
            _document_store.save_document(result, b"", "application/octet-stream", owner_token)
            _record_document_event(
                result,
                "scan_failed",
                f"Document denied because extraction or scanning failed: {error}",
            )
        results.append(result)
    return results


@app.post("/api/documents/{document_id}/approval", response_model=DocumentScanResult)
def approve_document(document_id: str, request: DocumentApproval) -> DocumentScanResult:
    stored = _document_store.get_document(document_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Document was not found.")
    _, _, document, owner_token = stored
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
) -> dict[str, str | bytes]:
    stored = _document_store.get_document(document_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Document was not found.")
    content, content_type, document, owner_token = stored
    if authorization != f"Bearer {owner_token}":
        raise HTTPException(status_code=403, detail="Document ownership could not be verified.")
    if document.status != "released":
        raise HTTPException(status_code=403, detail="Document is not released by TrustFirewall.")
    _record_document_event(document, "release", "Original document released through the TrustFirewall gateway.")
    from fastapi.responses import Response

    return Response(content=content, media_type=content_type, headers={"Content-Disposition": f'attachment; filename="{document.filename}"'})


@app.get("/api/document-audit", response_model=list[DocumentAuditEvent])
def document_audit_history() -> list[DocumentAuditEvent]:
    with _audit_lock:
        return _document_store.audit_history()


@app.post("/api/analyze", response_model=AnalysisResult)
def analyze_action(proposal: ActionProposal) -> AnalysisResult:
    with _audit_lock:
        history = tuple(_workflow_history.get(_workflow_key(proposal), ()))
    return analyze_proposal(proposal, history)


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
    )


@app.post("/api/intercept", response_model=InterceptResponse)
def intercept_action(proposal: ActionProposal) -> InterceptResponse:
    if proposal.approval_request_id:
        with _audit_lock:
            previous = _audit_events.get(proposal.approval_request_id)
            history = tuple(_workflow_history.get(_workflow_key(proposal), ()))
        if previous is None:
            raise HTTPException(status_code=404, detail="Approval request was not found.")
        if previous.status == "approved":
            analysis = analyze_proposal(proposal, history)
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
    analysis = analyze_proposal(proposal, history)
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
def audit_history() -> list[AuditEvent | DocumentAuditEvent]:
    with _audit_lock:
        events = [*list(_audit_events.values()), *_document_store.audit_history()]
        return sorted(events, key=lambda event: event.created_at, reverse=True)


@app.post("/api/audit/{request_id}/approval", response_model=AuditEvent)
def approve_intercept(request_id: str, request: ApprovalRequest) -> AuditEvent:
    with _audit_lock:
        event = _audit_events.get(request_id)
        if event is None:
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
