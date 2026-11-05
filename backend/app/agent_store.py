from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from uuid import uuid4


class AgentStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS agent_conversations (
                    conversation_id TEXT PRIMARY KEY,
                    owner_user_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agent_messages (
                    message_id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (conversation_id) REFERENCES agent_conversations(conversation_id)
                );
                """
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def create_conversation(self, owner_user_id: str) -> str:
        conversation_id = str(uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO agent_conversations VALUES (?, ?, ?, ?)",
                (conversation_id, owner_user_id, now, now),
            )
        return conversation_id

    def owns(self, conversation_id: str, owner_user_id: str) -> bool:
        with self._connect() as connection:
            return connection.execute(
                "SELECT 1 FROM agent_conversations WHERE conversation_id = ? AND owner_user_id = ?",
                (conversation_id, owner_user_id),
            ).fetchone() is not None

    def add_message(
        self,
        conversation_id: str,
        role: str,
        content: str,
        metadata: dict[str, object] | None = None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO agent_messages VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid4()), conversation_id, role, content, json.dumps(metadata or {}), now),
            )
            connection.execute(
                "UPDATE agent_conversations SET updated_at = ? WHERE conversation_id = ?",
                (now, conversation_id),
            )

    def messages(self, conversation_id: str) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT role, content, metadata_json, created_at FROM agent_messages WHERE conversation_id = ? ORDER BY created_at",
                (conversation_id,),
            ).fetchall()
        return [
            {
                "role": row["role"],
                "content": row["content"],
                "metadata": json.loads(row["metadata_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def list_conversations(self, owner_user_id: str) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT conversation_id, created_at, updated_at FROM agent_conversations WHERE owner_user_id = ? ORDER BY updated_at DESC",
                (owner_user_id,),
            ).fetchall()
        return [dict(row) for row in rows]
