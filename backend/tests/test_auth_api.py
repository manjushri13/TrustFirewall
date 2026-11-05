import tempfile
import unittest
import os
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from starlette.responses import Response


class AuthApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        from app.main import app
        import app.main as main_module
        from app.auth_store import AuthStore
        from app.agent_store import AgentStore
        from app.document_store import DocumentStore

        cls.main_module = main_module
        cls.original_document_store = main_module._document_store
        cls.original_auth_store = main_module._auth_store
        cls.original_agent_store = main_module._agent_store
        database_path = Path(cls.directory.name) / "auth.sqlite3"
        main_module._document_store = DocumentStore(database_path)
        main_module._auth_store = AuthStore(database_path)
        main_module._agent_store = AgentStore(database_path)
        cls.client = TestClient(app)
        cls.origin = "http://localhost:5173"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        cls.main_module._document_store = cls.original_document_store
        cls.main_module._auth_store = cls.original_auth_store
        cls.main_module._agent_store = cls.original_agent_store
        cls.directory.cleanup()

    def test_browser_authentication_flow(self) -> None:
        password = "secure-password-123"
        new_password = "new-secure-password-123"
        response = self.client.post(
            "/api/auth/register",
            json={"full_name": "Browser User", "email": "browser@example.com", "password": password},
            headers={"Origin": self.origin},
        )
        self.assertEqual(response.status_code, 201)
        self.assertIn("trustfirewall_session=", response.headers["set-cookie"])
        self.assertEqual(response.headers["access-control-allow-origin"], self.origin)
        self.assertEqual(response.headers["access-control-allow-credentials"], "true")
        self.assertEqual(self.client.get("/api/auth/me").status_code, 200)
        self.assertEqual(self.client.get("/api/documents/monitoring").status_code, 200)
        self.assertEqual(self.client.get("/api/agents/connections").status_code, 200)

        response = self.client.post(
            "/api/auth/change-password",
            json={
                "current_password": "wrong-password",
                "new_password": new_password,
                "confirm_password": new_password,
            },
        )
        self.assertEqual(response.status_code, 403)
        response = self.client.post(
            "/api/auth/change-password",
            json={
                "current_password": password,
                "new_password": new_password,
                "confirm_password": new_password,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            self.client.post(
                "/api/auth/login",
                json={"email": "browser@example.com", "password": password},
            ).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                "/api/auth/login",
                json={"email": "browser@example.com", "password": new_password},
            ).status_code,
            200,
        )
        self.assertEqual(self.client.post("/api/auth/logout").status_code, 204)
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)

    def test_localhost_cors_preflight_allows_credentials(self) -> None:
        response = self.client.options(
            "/api/auth/me",
            headers={
                "Origin": self.origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["access-control-allow-origin"], self.origin)
        self.assertEqual(response.headers["access-control-allow-credentials"], "true")

    def test_configured_frontend_origin_is_added_without_wildcard(self) -> None:
        with patch.dict(os.environ, {"TRUSTFIREWALL_FRONTEND_URL": "https://trustfirewall.vercel.app/"}):
            origins = self.main_module._configured_frontend_origins()
        self.assertIn("https://trustfirewall.vercel.app", origins)
        self.assertNotIn("*", origins)

    def test_cookie_settings_switch_for_secure_cross_site_deployment(self) -> None:
        response = Response()
        self.main_module._set_session_cookie(response, "test-token")
        self.assertIn("SameSite=lax", response.headers["set-cookie"])
        with patch.object(self.main_module, "_cookie_secure", True):
            secure_response = Response()
            self.main_module._set_session_cookie(secure_response, "test-token")
        self.assertIn("SameSite=none", secure_response.headers["set-cookie"])
        self.assertIn("Secure", secure_response.headers["set-cookie"])

    def test_health_is_public(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_all_stores_share_configured_database_path(self) -> None:
        self.assertEqual(self.main_module._document_store.path, self.main_module._auth_store.path)
        self.assertEqual(self.main_module._document_store.path, self.main_module._agent_store.path)

    def test_registration_rejects_duplicates_and_invalid_data(self) -> None:
        payload = {"full_name": "Duplicate User", "email": "duplicate@example.com", "password": "secure-password-123"}
        self.assertEqual(self.client.post("/api/auth/register", json=payload).status_code, 201)
        duplicate = self.client.post("/api/auth/register", json=payload)
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(duplicate.json()["detail"], "An account with that email already exists.")

        invalid = self.client.post(
            "/api/auth/register",
            json={"full_name": "", "email": "not-an-email", "password": "short"},
        )
        self.assertEqual(invalid.status_code, 422)

    def test_registration_hashes_password_and_new_user_can_login(self) -> None:
        payload = {"full_name": "New User", "email": "new-user@example.com", "password": "secure-password-123"}
        response = self.client.post("/api/auth/register", json=payload)
        self.assertEqual(response.status_code, 201)
        user_id = response.json()["user"]["user_id"]
        stored = self.main_module._auth_store.get_password_hash(user_id)
        self.assertIsNotNone(stored)
        self.assertTrue(stored.startswith("scrypt$"))
        self.assertNotEqual(stored, payload["password"])

        self.client.post("/api/auth/logout")
        login = self.client.post(
            "/api/auth/login",
            json={"email": payload["email"], "password": payload["password"]},
        )
        self.assertEqual(login.status_code, 200)

    def test_custom_mcp_connection_requires_configuration_and_is_owned(self) -> None:
        registered = self.client.post(
            "/api/auth/register",
            json={
                "full_name": "MCP User",
                "email": "mcp-user@example.com",
                "password": "secure-password-123",
            },
        )
        self.assertEqual(registered.status_code, 201)
        missing_command = self.client.post(
            "/api/agents/connections",
            json={"provider": "custom"},
        )
        self.assertEqual(missing_command.status_code, 422)
        created = self.client.post(
            "/api/agents/connections",
            json={
                "provider": "custom",
                "mcp_command": "python demo_mcp_server.py",
            },
        )
        self.assertEqual(created.status_code, 200)
        self.assertEqual(created.json()["status"], "configured")
        self.assertEqual(created.json()["mcp_command"], "python demo_mcp_server.py")
        connection_id = created.json()["connection_id"]
        self.assertEqual(self.client.delete(f"/api/agents/connections/{connection_id}").status_code, 204)

    def test_agent_chat_and_document_scan_require_auth_and_preserve_ownership(self) -> None:
        with patch("app.main.generate_response", return_value="Gemini response."):
            unauthenticated = self.client.post("/api/agent/chat", json={"message": "Hello"})
            self.assertEqual(unauthenticated.status_code, 401)
            registered = self.client.post(
                "/api/auth/register",
                json={
                    "full_name": "Agent User",
                    "email": "agent-user@example.com",
                    "password": "secure-password-123",
                },
            )
            self.assertEqual(registered.status_code, 201)
            chat = self.client.post("/api/agent/chat", json={"message": "Hello"})
            self.assertEqual(chat.status_code, 200)
            self.assertEqual(chat.json()["message"], "Gemini response.")
            conversation_id = chat.json()["conversation_id"]
            history = self.client.get(f"/api/agent/conversations/{conversation_id}")
            self.assertEqual(len(history.json()["messages"]), 2)

        with patch("app.main.analyze_document_text", return_value=[]):
            scanned = self.client.post(
                "/api/agent/documents/scan",
                files=[("files", ("agent.txt", b"Ordinary notes.", "text/plain"))],
            )
        self.assertEqual(scanned.status_code, 200)
        document_id = scanned.json()[0]["document_id"]
        with patch("app.main.generate_response", return_value="Document response."):
            self.assertEqual(
                self.client.post(
                    "/api/agent/chat",
                    json={"conversation_id": conversation_id, "message": "What is this?", "document_ids": [document_id]},
                ).status_code,
                200,
            )

    def test_agent_tools_block_delete_and_reject_path_traversal(self) -> None:
        self.client.post(
            "/api/auth/register",
            json={
                "full_name": "Tool User",
                "email": "tool-user@example.com",
                "password": "secure-password-123",
            },
        )
        blocked = self.client.post(
            "/api/agent/tools/call",
            json={"tool": "delete_file_simulation", "arguments": {}},
        )
        self.assertEqual(blocked.status_code, 200)
        self.assertEqual(blocked.json()["decision"], "block")
        traversal = self.client.post(
            "/api/agent/tools/call",
            json={"tool": "read_file", "arguments": {"path": "..\\secret.txt"}},
        )
        self.assertEqual(traversal.status_code, 400)

    def test_agent_upload_rejects_unauthenticated_unsupported_and_oversized_files(self) -> None:
        self.client.cookies.clear()
        unauthenticated = self.client.post(
            "/api/agent/documents/scan",
            files=[("files", ("notes.txt", b"notes", "text/plain"))],
        )
        self.assertEqual(unauthenticated.status_code, 401)
        self.client.post(
            "/api/auth/register",
            json={
                "full_name": "Upload User",
                "email": "upload-user@example.com",
                "password": "secure-password-123",
            },
        )
        unsupported = self.client.post(
            "/api/agent/documents/scan",
            files=[("files", ("notes.exe", b"not an executable", "application/octet-stream"))],
        )
        self.assertEqual(unsupported.status_code, 415)
        oversized = self.client.post(
            "/api/agent/documents/scan",
            files=[("files", ("large.txt", b"x" * (10 * 1024 * 1024 + 1), "text/plain"))],
        )
        self.assertEqual(oversized.status_code, 413)
