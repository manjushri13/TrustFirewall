import unittest
from datetime import datetime, timezone

from pydantic import ValidationError

from app.models import (
    DocumentClassification,
    DocumentFinding,
    DocumentProvenance,
    DocumentScanResult,
    SourceType,
    TrustLevel,
)


class DocumentModelTests(unittest.TestCase):
    def test_document_provenance_defaults_to_document_and_untrusted(self) -> None:
        provenance = DocumentProvenance(
            source_id="document-1",
            filename="notes.txt",
            content_type="text/plain",
            content_sha256="abc123",
        )

        self.assertEqual(provenance.source_type, SourceType.DOCUMENT)
        self.assertEqual(provenance.trust_level, TrustLevel.UNTRUSTED)
        self.assertIsNotNone(provenance.created_at.tzinfo)

    def test_document_provenance_rejects_non_document_source_type(self) -> None:
        with self.assertRaises(ValidationError):
            DocumentProvenance(
                source_id="document-1",
                source_type=SourceType.WEB_CONTENT,
                filename="notes.txt",
                content_type="text/plain",
                content_sha256="abc123",
            )

    def test_document_provenance_validates_required_fields(self) -> None:
        with self.assertRaises(ValidationError):
            DocumentProvenance(
                source_id="",
                filename="notes.txt",
                content_type="text/plain",
                content_sha256="abc123",
            )

    def test_document_scan_result_remains_backward_compatible_without_provenance(self) -> None:
        result = DocumentScanResult(
            document_id="document-1",
            owner_token="owner-token",
            filename="notes.txt",
            classification=DocumentClassification.SAFE,
            status="released",
            extracted_line_count=1,
            created_at=datetime.now(timezone.utc),
        )

        self.assertIsNone(result.provenance)

    def test_document_finding_accepts_optional_provenance_fields(self) -> None:
        finding = DocumentFinding(
            filename="notes.txt",
            line_number=1,
            detected_text="instruction",
            severity=DocumentClassification.SUSPICIOUS,
            explanation="Suspicious instruction.",
            rule_id="DOC-001",
            source_id="document-1",
            content_sha256="abc123",
        )

        self.assertEqual(finding.source_id, "document-1")
        self.assertEqual(finding.content_sha256, "abc123")
