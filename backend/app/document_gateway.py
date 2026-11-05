from __future__ import annotations

import io
import hashlib
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePath
from typing import BinaryIO

from docx import Document
from pypdf import PdfReader
import xlrd

from .models import (
    DocumentClassification,
    DocumentFinding,
    DocumentProvenance,
)


SUPPORTED_EXTENSIONS = {".txt", ".pdf", ".docx", ".csv", ".xlsx", ".xls"}


@dataclass(frozen=True)
class ExtractedDocument:
    text: str
    content_type: str


def create_document_provenance(
    document_id: str,
    filename: str,
    content: bytes,
    content_type: str,
) -> DocumentProvenance:
    return DocumentProvenance(
        source_id=document_id,
        filename=filename,
        content_type=content_type,
        content_sha256=hashlib.sha256(content).hexdigest(),
        created_at=datetime.now(timezone.utc),
    )


def extract_text(filename: str, content: bytes) -> ExtractedDocument:
    extension = PurePath(filename).suffix.lower()
    if extension == ".txt":
        return ExtractedDocument(content.decode("utf-8"), "text/plain")
    if extension == ".pdf":
        reader = PdfReader(io.BytesIO(content))
        return ExtractedDocument(
            "\n".join(page.extract_text() or "" for page in reader.pages),
            "application/pdf",
        )
    if extension == ".docx":
        document = Document(io.BytesIO(content))
        paragraphs = [paragraph.text for paragraph in document.paragraphs]
        return ExtractedDocument("\n".join(paragraphs), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    if extension == ".csv":
        return ExtractedDocument(content.decode("utf-8-sig"), "text/csv")
    if extension == ".xlsx":
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            shared = []
            if "xl/sharedStrings.xml" in archive.namelist():
                shared = re.findall(r"<t[^>]*>(.*?)</t>", archive.read("xl/sharedStrings.xml").decode("utf-8"))
            sheets = []
            for name in archive.namelist():
                if name.startswith("xl/worksheets/") and name.endswith(".xml"):
                    raw = archive.read(name).decode("utf-8")
                    values = re.findall(r"<v>(.*?)</v>", raw)
                    sheets.append(" ".join(shared[int(value)] if value.isdigit() and int(value) < len(shared) else value for value in values))
            return ExtractedDocument("\n".join(sheets), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    if extension == ".xls":
        workbook = xlrd.open_workbook(file_contents=content, on_demand=True)
        rows = []
        for sheet in workbook.sheets():
            rows.extend(" ".join(str(value) for value in sheet.row_values(index)) for index in range(sheet.nrows))
        return ExtractedDocument("\n".join(rows), "application/vnd.ms-excel")
    raise ValueError("The document format is not supported.")


_RULES: tuple[tuple[str, str, str, str], ...] = (
    (
        "DOC-OVERRIDE",
        "MALICIOUS",
        r"\b(?:ignore|disregard|override|forget)\b.{0,80}\b(?:previous|prior|system|developer|security)\b",
        "Attempts to override previous, system, developer, or security instructions.",
    ),
    (
        "DOC-CONFIDENTIAL-DISCLOSURE",
        "MALICIOUS",
        r"\b(?:reveal| disclose|show|print|expose)\b.{0,80}\b(?:confidential|secret|system prompt|credentials|private)\b",
        "Requests disclosure of confidential information or protected instructions.",
    ),
    (
        "DOC-EXTERNAL-TRANSFER",
        "MALICIOUS",
        r"\b(?:send|upload|email|post|transfer|exfiltrate)\b.{0,100}\b(?:file|document|data|credential|secret|externally|attacker|https?://|@)",
        "Instructs the agent to send sensitive material to an external destination.",
    ),
    (
        "DOC-TASK-REDIRECT",
        "SUSPICIOUS",
        r"\b(?:stop|cancel|abandon)\b.{0,80}\b(?:task|execution|current)\b|\bunrelated task\b",
        "Attempts to stop the current task and redirect the agent to unrelated work.",
    ),
    (
        "DOC-SECURITY-BYPASS",
        "MALICIOUS",
        r"\b(?:hide|conceal|bypass|disable|avoid)\b.{0,80}\b(?:security|audit|logging|approval|firewall|user)\b",
        "Attempts to conceal actions or bypass security controls.",
    ),
)


def scan_text(
    filename: str,
    text: str,
    source_id: str | None = None,
    content_sha256: str | None = None,
) -> tuple[DocumentClassification, list[DocumentFinding]]:
    findings: list[DocumentFinding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule_id, severity, pattern, explanation in _RULES:
            match = re.search(pattern, line, flags=re.IGNORECASE)
            if match:
                findings.append(
                    DocumentFinding(
                        filename=filename,
                        line_number=line_number,
                        detected_text=line,
                        severity=severity,
                        explanation=explanation,
                        rule_id=rule_id,
                        source_id=source_id,
                        content_sha256=content_sha256,
                    )
                )
    if any(item.severity == "MALICIOUS" for item in findings):
        return DocumentClassification.MALICIOUS, findings
    if findings:
        return DocumentClassification.SUSPICIOUS, findings
    return DocumentClassification.SAFE, findings
