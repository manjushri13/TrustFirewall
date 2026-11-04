from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Iterator

from .models import DocumentAuditEvent, DocumentMonitorItem, DocumentScanResult


def _default_path() -> Path:
    return Path(
        os.getenv(
            "TRUSTFIREWALL_DOCUMENT_DB",
            str(Path(__file__).resolve().parents[1] / "trustfirewall_documents.sqlite3"),
        )
    )


class DocumentStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        except Exception:
            connection.rollback()
            raise
        else:
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    document_id TEXT PRIMARY KEY,
                    content BLOB NOT NULL,
                    content_type TEXT NOT NULL,
                    owner_token TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    owner_user_id TEXT
                );
                CREATE TABLE IF NOT EXISTS document_confirmations (
                    document_id TEXT NOT NULL,
                    approver_id TEXT NOT NULL,
                    PRIMARY KEY (document_id, approver_id),
                    FOREIGN KEY (document_id) REFERENCES documents(document_id)
                );
                CREATE TABLE IF NOT EXISTS document_audit (
                    event_id TEXT PRIMARY KEY,
                    document_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(documents)")}
            if "owner_user_id" not in columns:
                connection.execute("ALTER TABLE documents ADD COLUMN owner_user_id TEXT")

    def save_document(
        self,
        document: DocumentScanResult,
        content: bytes,
        content_type: str,
        owner_token: str,
        owner_user_id: str | None = None,
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO documents
                    (document_id, content, content_type, owner_token, result_json, owner_user_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    document.document_id,
                    content,
                    content_type,
                    owner_token,
                    document.model_dump_json(),
                    owner_user_id,
                ),
            )

    def get_document(
        self,
        document_id: str,
    ) -> tuple[bytes, str, DocumentScanResult, str] | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM documents WHERE document_id = ?",
                (document_id,),
            ).fetchone()
        if row is None:
            return None
        return (
            bytes(row["content"]),
            row["content_type"],
            DocumentScanResult.model_validate_json(row["result_json"]),
            row["owner_token"],
        )

    def get_document_owner(self, document_id: str) -> str | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT owner_user_id FROM documents WHERE document_id = ?",
                (document_id,),
            ).fetchone()
        return row["owner_user_id"] if row else None

    def list_documents(self, owner_user_id: str | None = None) -> list[DocumentMonitorItem]:
        with self._lock, self._connect() as connection:
            if owner_user_id is None:
                rows = connection.execute("SELECT result_json FROM documents ORDER BY rowid DESC").fetchall()
            else:
                rows = connection.execute(
                    "SELECT result_json FROM documents WHERE owner_user_id = ? ORDER BY rowid DESC",
                    (owner_user_id,),
                ).fetchall()
        return [
            DocumentMonitorItem.model_validate_json(row["result_json"])
            for row in rows
        ]

    def update_document(self, document: DocumentScanResult) -> None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM documents WHERE document_id = ?",
                (document.document_id,),
            ).fetchone()
            if row is not None and document.provenance is None:
                stored = DocumentScanResult.model_validate_json(row["result_json"])
                document = document.model_copy(update={"provenance": stored.provenance})
            connection.execute(
                "UPDATE documents SET result_json = ? WHERE document_id = ?",
                (document.model_dump_json(), document.document_id),
            )

    def add_confirmation(self, document_id: str, approver_id: str) -> bool:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO document_confirmations (document_id, approver_id)
                VALUES (?, ?)
                """,
                (document_id, approver_id),
            )
            return cursor.rowcount == 1

    def confirmation_count(self, document_id: str) -> int:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM document_confirmations WHERE document_id = ?",
                (document_id,),
            ).fetchone()
        return int(row["count"])

    def add_audit(self, event: DocumentAuditEvent) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO document_audit
                    (event_id, document_id, filename, event_type, classification, detail, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.document_id,
                    event.filename,
                    event.event_type,
                    event.classification.value,
                    event.detail,
                    event.created_at.isoformat(),
                ),
            )

    def audit_history(self, owner_user_id: str | None = None) -> list[DocumentAuditEvent]:
        with self._lock, self._connect() as connection:
            if owner_user_id is None:
                rows = connection.execute("SELECT * FROM document_audit ORDER BY created_at DESC").fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT document_audit.* FROM document_audit
                    JOIN documents ON documents.document_id = document_audit.document_id
                    WHERE documents.owner_user_id = ? ORDER BY document_audit.created_at DESC
                    """,
                    (owner_user_id,),
                ).fetchall()
        return [
            DocumentAuditEvent(
                event_id=row["event_id"],
                document_id=row["document_id"],
                filename=row["filename"],
                event_type=row["event_type"],
                classification=row["classification"],
                detail=row["detail"],
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]
