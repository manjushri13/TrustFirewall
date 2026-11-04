import tempfile
import unittest
from pathlib import Path

from app.auth_store import AuthStore


class AuthStoreTests(unittest.TestCase):
    def test_password_sessions_and_logout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = AuthStore(Path(directory) / "auth.sqlite3")
            user = store.create_user("User A", "a@example.com", "a-secure-password")
            token = store.create_session(user.user_id)
            self.assertEqual(store.get_session_user(token).user_id, user.user_id)
            self.assertIsNone(store.authenticate(user.email, "wrong-password"))
            self.assertEqual(store.authenticate(user.email, "a-secure-password").user_id, user.user_id)
            store.delete_session(token)
            self.assertIsNone(store.get_session_user(token))

    def test_connections_are_scoped_to_the_user(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = AuthStore(Path(directory) / "auth.sqlite3")
            user_a = store.create_user("User A", "a@example.com", "a-secure-password")
            user_b = store.create_user("User B", "b@example.com", "b-secure-password")
            connection = store.upsert_connection(user_a.user_id, "custom", "connected")
            self.assertEqual([connection.connection_id], [item.connection_id for item in store.list_connections(user_a.user_id)])
            self.assertEqual([], store.list_connections(user_b.user_id))
            self.assertFalse(store.delete_connection(user_b.user_id, connection.connection_id))
            self.assertEqual(1, len(store.list_connections(user_a.user_id)))
