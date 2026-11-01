import re
from collections.abc import Sequence

from .models import (
    ActionProposal,
    ActionStep,
    AnalysisResult,
    Decision,
    Evidence,
    ProvenanceSource,
)


PROMPT_INJECTION_PATTERNS = (
    r"ignore (?:(?:all|any|previous|prior)\s+){1,2}instructions",
    r"disregard (all|any|previous|prior) instructions",
    r"reveal (the )?(system|developer) prompt",
    r"override (the )?(security|system) policy",
    r"do not tell the user",
)


def _contains_any(text: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def _is_sensitive_read(step: ActionStep) -> bool:
    text = f"{step.action_type} {step.description} {step.target or ''}".lower()
    permissions = {permission.lower() for permission in step.permissions}
    return (
        "read_sensitive" in permissions
        or "credential" in text
        or "secret" in text
        or "private file" in text
        or "sensitive data" in text
    )


def _is_external_transfer(step: ActionStep) -> bool:
    text = f"{step.action_type} {step.description} {step.target or ''}".lower()
    permissions = {permission.lower() for permission in step.permissions}
    return (
        "network_egress" in permissions
        or "external" in text
        or "upload" in text
        or "send" in text
        or "post" in text
    )


def _is_hiding(step: ActionStep) -> bool:
    text = f"{step.action_type} {step.description} {step.target or ''}".lower()
    return any(
        phrase in text
        for phrase in ("delete logs", "clear history", "hide", "cover tracks", "disable audit")
    )


def _trusted_sources(provenance: list[ProvenanceSource]) -> list[ProvenanceSource]:
    return [
        source
        for source in provenance
        if source.is_backend_trusted
    ]


def _action_label(step: ActionStep) -> str:
    return f"{step.action_type}: {step.description}"


def _provenance_ids(step: ActionStep) -> set[str]:
    return {
        *[source.source_id for source in step.provenance],
        *step.provenance_refs,
        *[
            source.parent_source_id
            for source in step.provenance
            if source.parent_source_id
        ],
    }


def _data_flow_tokens(step: ActionStep) -> set[str]:
    text = f"{step.description} {step.target or ''}".lower()
    ignored = {
        "read",
        "file",
        "data",
        "external",
        "endpoint",
        "upload",
        "send",
        "post",
        "the",
        "this",
        "from",
        "to",
    }
    return {
        token
        for token in re.findall(r"[a-z0-9_]+", text)
        if len(token) >= 4 and token not in ignored
    }


def _steps_are_related(
    first: ActionStep,
    second: ActionStep,
) -> bool:
    return bool(
        _provenance_ids(first) & _provenance_ids(second)
        or _data_flow_tokens(first) & _data_flow_tokens(second)
    )


def _resolve_sources(
    step: ActionStep,
    known_sources: dict[str, ProvenanceSource],
) -> tuple[list[ProvenanceSource], list[str]]:
    sources = list(step.provenance)
    missing_refs: list[str] = []
    refs = list(step.provenance_refs)
    refs.extend(
        source.parent_source_id
        for source in step.provenance
        if source.parent_source_id
    )
    for source_id in refs:
        source = known_sources.get(source_id)
        if source is None:
            missing_refs.append(source_id)
        elif source.source_id not in {item.source_id for item in sources}:
            sources.append(source)
    return sources, missing_refs


def analyze_proposal(
    proposal: ActionProposal,
    history: Sequence[ActionProposal] = (),
) -> AnalysisResult:
    evidence: list[Evidence] = []
    score = 0
    known_sources = {
        source.source_id: source
        for previous in history
        for step in [*previous.sequence, previous]
        for source in step.provenance
    }
    known_sources.update(
        {
            source.source_id: source
            for step in [*proposal.sequence, proposal]
            for source in step.provenance
        }
    )
    proposal_sources, missing_refs = _resolve_sources(proposal, known_sources)
    current_steps = [*proposal.sequence, proposal]
    resolved_steps: list[tuple[ActionStep, list[ProvenanceSource]]] = []
    for step in current_steps:
        sources, step_missing_refs = _resolve_sources(step, known_sources)
        missing_refs.extend(step_missing_refs)
        if not sources:
            sources = list(proposal_sources)
        resolved_steps.append((step, sources))
    all_steps = [
        (step, sources)
        for previous in history
        for step in [*previous.sequence, previous]
        for sources, _ in [_resolve_sources(step, known_sources)]
    ]
    all_steps.extend(resolved_steps)

    if not proposal_sources and not proposal.provenance_refs:
        score += 35
        evidence.append(
            Evidence(
                rule_id="PROVENANCE-MISSING",
                severity=Decision.FLAG,
                title="Instruction provenance is missing",
                detail="The action cannot be attributed to a known instruction source.",
            )
        )
    if missing_refs:
        score += 35
        evidence.append(
            Evidence(
                rule_id="PROVENANCE-UNRESOLVED",
                severity=Decision.FLAG,
                title="A provenance reference could not be resolved",
                detail=f"Unknown source reference(s): {', '.join(sorted(set(missing_refs)))}. "
                "Unresolved provenance is never treated as trusted.",
                source_ids=sorted(set(missing_refs)),
            )
        )

    current_sources = [
        source
        for _, sources in resolved_steps
        for source in sources
    ]
    injection_sources = [
        source
        for source in current_sources
        if _contains_any(source.content, PROMPT_INJECTION_PATTERNS)
    ]
    if injection_sources:
        score += 45
        evidence.append(
            Evidence(
                rule_id="PROMPT-INJECTION",
                severity=Decision.BLOCK,
                title="Instruction override attempt detected",
                detail="A provenance source attempts to override existing instructions or conceal behavior.",
                source_ids=[source.source_id for source in injection_sources],
            )
        )

    untrusted_sources = [
        source
        for source in current_sources
        if not source.is_backend_trusted
    ]
    if untrusted_sources and (_is_external_transfer(proposal) or _is_sensitive_read(proposal)):
        score += 25
        evidence.append(
            Evidence(
                rule_id="UNTRUSTED-SENSITIVE-ACTION",
                severity=Decision.FLAG,
                title="Sensitive action is influenced by an untrusted source",
                detail="Sensitive reads and external effects require a trusted instruction chain.",
                source_ids=[source.source_id for source in untrusted_sources],
            )
        )

    if len(all_steps) >= 2:
        has_hiding = any(_is_hiding(step) for step, _ in all_steps)
        has_external_transfer = any(
            _is_external_transfer(step) for step, _ in all_steps
        )
        related_pairs = [
            (read_step, transfer_step)
            for read_step, _ in all_steps
            for transfer_step, _ in all_steps
            if _is_sensitive_read(read_step)
            and _is_external_transfer(transfer_step)
            and read_step is not transfer_step
            and _steps_are_related(read_step, transfer_step)
        ]
        if related_pairs:
            score += 40
            chain = " -> ".join(_action_label(step) for step, _ in all_steps)
            chain_sources = sorted(
                {
                    source.source_id
                    for _, sources in all_steps
                    for source in sources
                    if not source.is_backend_trusted
                }
            )
            evidence.append(
                Evidence(
                    rule_id="DATA-EXFILTRATION-CHAIN",
                    severity=Decision.BLOCK,
                    title="Sensitive read combined with external transfer",
                    detail=f"Action chain: {chain}. "
                    f"Untrusted provenance links: {', '.join(chain_sources) or 'none'}.",
                    source_ids=chain_sources,
                )
            )
        if has_external_transfer and has_hiding:
            score += 30
            chain = " -> ".join(_action_label(step) for step, _ in all_steps)
            evidence.append(
                Evidence(
                    rule_id="AUDIT-EVASION",
                    severity=Decision.BLOCK,
                    title="External transfer is paired with audit evasion",
                    detail=f"Action chain: {chain}. The sequence attempts to conceal an external side effect.",
                )
            )

    trusted_text = " ".join(source.content.lower() for source in _trusted_sources(current_sources))
    if ("never upload" in trusted_text or "do not send" in trusted_text) and _is_external_transfer(
        proposal
    ):
        score += 40
        evidence.append(
            Evidence(
                rule_id="TRUST-CONFLICT",
                severity=Decision.BLOCK,
                title="Action conflicts with a trusted instruction",
                detail="A trusted instruction explicitly prohibits the proposed external transfer.",
                source_ids=[source.source_id for source in _trusted_sources(current_sources)],
            )
        )

    has_block = any(item.severity == Decision.BLOCK for item in evidence)
    decision = (
        Decision.BLOCK
        if has_block
        else Decision.FLAG
        if evidence or score >= 35
        else Decision.ALLOW
    )
    score = min(score, 100)
    next_step = {
        Decision.ALLOW: "Proceed with simulated execution and retain the audit record.",
        Decision.FLAG: "Request human review and verify the instruction provenance.",
        Decision.BLOCK: "Keep the proposal blocked; investigate the evidence before retrying.",
    }[decision]

    return AnalysisResult(
        action_id=proposal.action_id,
        decision=decision,
        risk_score=score,
        evidence=evidence,
        recommended_next_step=next_step,
    )
