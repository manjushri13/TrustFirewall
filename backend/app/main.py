from datetime import datetime, timezone
from threading import Lock
from uuid import uuid4

from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .models import (
    ActionProposal,
    AnalysisResult,
    ApprovalRequest,
    AuditEvent,
    Decision,
    InterceptResponse,
)
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
_audit_lock = Lock()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "demo"}


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


@app.get("/api/audit", response_model=list[AuditEvent])
def audit_history() -> list[AuditEvent]:
    with _audit_lock:
        return list(reversed(list(_audit_events.values())))


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
