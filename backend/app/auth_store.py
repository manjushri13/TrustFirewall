from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from pydantic import BaseModel


class UserRecord(BaseModel):
    user_id: str
    full_name: str
    email: str
    profile_image_url: str | None = None
    provider: str
    email_verified: bool = False
    created_at: datetime


class AgentConnectionRecord(BaseModel):
    connection_id: str
    user_id: str
    provider: str
    display_name: str
    status: str
    created_at: datetime
    updated_at: datetime


def _db_path() -> Path:
    return Path(os.getenv("TRUSTFIREWALL_DOCUMENT_DB", "trustfirewall_documents.sqlite3"))


class AuthStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT,
                    profile_image_url TEXT,
                    provider TEXT NOT NULL,
                    google_subject TEXT UNIQUE,
                    email_verified INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    session_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                );
                CREATE TABLE IF NOT EXISTS agent_connections (
                    connection_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(user_id, provider),
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                );
                CREATE TABLE IF NOT EXISTS oauth_states (
                    state_hash TEXT PRIMARY KEY,
                    nonce_hash TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS email_verification_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used_at TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                );
                """
            )
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
            if "google_subject" not in columns:
                connection.execute("ALTER TABLE users ADD COLUMN google_subject TEXT")
            if "email_verified" not in columns:
                connection.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")

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

    @staticmethod
    def hash_password(password: str) -> str:
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        return f"scrypt${salt.hex()}${digest.hex()}"

    @staticmethod
    def verify_password(password: str, stored: str) -> bool:
        try:
            _, salt_hex, digest_hex = stored.split("$")
            actual = hashlib.scrypt(
                password.encode(),
                salt=bytes.fromhex(salt_hex),
                n=2**14,
                r=8,
                p=1,
            )
            return hmac.compare_digest(actual.hex(), digest_hex)
        except (ValueError, TypeError):
            return False

    def create_user(self, full_name: str, email: str, password: str) -> UserRecord:
        now = datetime.now(timezone.utc).isoformat()
        user_id = secrets.token_urlsafe(18)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO users
                    (user_id, full_name, email, password_hash, provider, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'password', ?, ?)
                """,
                (user_id, full_name, email.lower(), self.hash_password(password), now, now),
            )
        return self.get_user(user_id)

    def get_user(self, user_id: str) -> UserRecord:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT user_id, full_name, email, profile_image_url, provider, email_verified, created_at FROM users WHERE user_id = ? AND status = 'active'",
                (user_id,),
            ).fetchone()
        if row is None:
            raise LookupError("User was not found.")
        values = dict(row)
        values["created_at"] = datetime.fromisoformat(row["created_at"])
        values["email_verified"] = bool(values["email_verified"])
        return UserRecord(**values)

    def authenticate(self, email: str, password: str) -> UserRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT user_id, password_hash FROM users WHERE email = ? AND status = 'active'",
                (email.lower(),),
            ).fetchone()
        if row is None or not row["password_hash"] or not self.verify_password(password, row["password_hash"]):
            return None
        return self.get_user(row["user_id"])

    def create_session(self, user_id: str, days: int = 7) -> str:
        token = secrets.token_urlsafe(32)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO sessions (session_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (
                    hashlib.sha256(token.encode()).hexdigest(),
                    user_id,
                    (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(),
                ),
            )
        return token

    def get_session_user(self, token: str) -> UserRecord | None:
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT user_id, expires_at FROM sessions WHERE session_hash = ?",
                (digest,),
            ).fetchone()
        if row is None or datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
            return None
        try:
            return self.get_user(row["user_id"])
        except LookupError:
            return None

    def delete_session(self, token: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM sessions WHERE session_hash = ?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            )

    def revoke_other_sessions(self, user_id: str, current_token: str | None = None) -> None:
        with self._connect() as connection:
            if current_token:
                connection.execute(
                    "DELETE FROM sessions WHERE user_id = ? AND session_hash != ?",
                    (user_id, hashlib.sha256(current_token.encode()).hexdigest()),
                )
            else:
                connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    def get_password_hash(self, user_id: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute("SELECT password_hash FROM users WHERE user_id = ?", (user_id,)).fetchone()
        return row["password_hash"] if row else None

    def change_password(self, user_id: str, password: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE users SET password_hash = ?, updated_at = ? WHERE user_id = ?",
                (self.hash_password(password), datetime.now(timezone.utc).isoformat(), user_id),
            )

    def create_oauth_state(self, nonce: str, minutes: int = 10) -> str:
        state = secrets.token_urlsafe(32)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO oauth_states (state_hash, nonce_hash, expires_at) VALUES (?, ?, ?)",
                (
                    hashlib.sha256(state.encode()).hexdigest(),
                    hashlib.sha256(nonce.encode()).hexdigest(),
                    (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat(),
                ),
            )
        return state

    def consume_oauth_state(self, state: str, nonce: str) -> bool:
        digest = hashlib.sha256(state.encode()).hexdigest()
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM oauth_states WHERE state_hash = ?", (digest,)).fetchone()
            connection.execute("DELETE FROM oauth_states WHERE state_hash = ?", (digest,))
        return bool(
            row
            and datetime.fromisoformat(row["expires_at"]) > datetime.now(timezone.utc)
            and hmac.compare_digest(row["nonce_hash"], hashlib.sha256(nonce.encode()).hexdigest())
        )

    def create_verification_token(self, user_id: str, hours: int = 24) -> str:
        token = secrets.token_urlsafe(32)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO email_verification_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (hashlib.sha256(token.encode()).hexdigest(), user_id, (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()),
            )
        return token

    def consume_verification_token(self, token: str) -> UserRecord | None:
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT user_id, expires_at, used_at FROM email_verification_tokens WHERE token_hash = ?",
                (digest,),
            ).fetchone()
            if not row or row["used_at"] or datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
                return None
            connection.execute("UPDATE email_verification_tokens SET used_at = ? WHERE token_hash = ?", (datetime.now(timezone.utc).isoformat(), digest))
            connection.execute("UPDATE users SET email_verified = 1, updated_at = ? WHERE user_id = ?", (datetime.now(timezone.utc).isoformat(), row["user_id"]))
        return self.get_user(row["user_id"])

    def find_google_user(self, subject: str) -> UserRecord | None:
        with self._connect() as connection:
            row = connection.execute("SELECT user_id FROM users WHERE google_subject = ? AND status = 'active'", (subject,)).fetchone()
        return self.get_user(row["user_id"]) if row else None

    def create_google_user(self, full_name: str, email: str, subject: str, profile_image_url: str | None) -> UserRecord:
        now = datetime.now(timezone.utc).isoformat()
        user_id = secrets.token_urlsafe(18)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO users (user_id, full_name, email, profile_image_url, provider, google_subject, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, 'google', ?, 1, ?, ?)",
                (user_id, full_name, email.lower(), profile_image_url, subject, now, now),
            )
        return self.get_user(user_id)

    def update_user(self, user_id: str, full_name: str, profile_image_url: str | None) -> UserRecord:
        with self._connect() as connection:
            connection.execute(
                "UPDATE users SET full_name = ?, profile_image_url = ?, updated_at = ? WHERE user_id = ?",
                (full_name, profile_image_url, datetime.now(timezone.utc).isoformat(), user_id),
            )
        return self.get_user(user_id)

    def list_connections(self, user_id: str) -> list[AgentConnectionRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM agent_connections WHERE user_id = ? ORDER BY created_at",
                (user_id,),
            ).fetchall()
        records = []
        for row in rows:
            values = dict(row)
            values["created_at"] = datetime.fromisoformat(row["created_at"])
            values["updated_at"] = datetime.fromisoformat(row["updated_at"])
            records.append(AgentConnectionRecord(**values))
        return records

    def upsert_connection(self, user_id: str, provider: str, status: str) -> AgentConnectionRecord:
        now = datetime.now(timezone.utc).isoformat()
        connection_id = secrets.token_urlsafe(18)
        display_name = {"chatgpt": "ChatGPT", "claude": "Claude", "gemini": "Google Gemini", "custom": "Custom agent"}.get(provider, provider)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO agent_connections
                    (connection_id, user_id, provider, display_name, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id, provider) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at
                """,
                (connection_id, user_id, provider, display_name, status, now, now),
            )
            row = connection.execute(
                "SELECT * FROM agent_connections WHERE user_id = ? AND provider = ?",
                (user_id, provider),
            ).fetchone()
        values = dict(row)
        values["created_at"] = datetime.fromisoformat(row["created_at"])
        values["updated_at"] = datetime.fromisoformat(row["updated_at"])
        return AgentConnectionRecord(**values)

    def delete_connection(self, user_id: str, connection_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM agent_connections WHERE connection_id = ? AND user_id = ?",
                (connection_id, user_id),
            )
        return cursor.rowcount == 1
