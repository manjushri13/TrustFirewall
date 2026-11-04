import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from app.document_store import DocumentStore
from app.models import (
    DocumentClassification,
    DocumentProvenance,
    DocumentScanResult,
    SourceType,
    TrustLevel,
)


def document_result(provenance: DocumentProvenance | None) -> DocumentScanResult:
    return DocumentScanResult(
        document_id="document-1",
        owner_token="owner-token",
        filename="notes.txt",
        classification=DocumentClassification.SUSPICIOUS,
        status="pending_approval",
        provenance=provenance,
        extracted_line_count=1,
        created_at=datetime.now(timezone.utc),
    )


class DocumentStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.database_directory.name) / "documents.sqlite3"
        self.store = DocumentStore(self.database_path)
        self.provenance = DocumentProvenance(
            source_id="document-1",
            filename="notes.txt",
            content_type="text/plain",
            content_sha256="abc123",
        )

    def tearDown(self) -> None:
        self.database_directory.cleanup()

    def test_provenance_round_trips_through_sqlite(self) -> None:
        self.store.save_document(
            document_result(self.provenance),
            b"notes",
            "text/plain",
            "owner-token",
        )

        stored = self.store.get_document("document-1")
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(stored[2].provenance, self.provenance)
        self.assertEqual(stored[3], "owner-token")

    def test_legacy_record_without_provenance_is_readable(self) -> None:
        legacy = document_result(None).model_dump(exclude={"provenance"})
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                """
                INSERT INTO documents
                    (document_id, content, content_type, owner_token, result_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                ("document-1", b"notes", "text/plain", "owner-token", json.dumps(legacy, default=str)),
            )
            connection.commit()
        finally:
            connection.close()

        stored = self.store.get_document("document-1")
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertIsNone(stored[2].provenance)

    def test_update_preserves_existing_provenance_when_omitted(self) -> None:
        self.store.save_document(
            document_result(self.provenance),
            b"notes",
            "text/plain",
            "owner-token",
        )

        updated = document_result(None).model_copy(update={"status": "released"})
        self.store.update_document(updated)

        stored = self.store.get_document("document-1")
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(stored[2].status, "released")
        self.assertEqual(stored[2].provenance, self.provenance)
