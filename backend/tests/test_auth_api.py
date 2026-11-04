import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient


class AuthApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        from app.main import app
        import app.main as main_module
        from app.auth_store import AuthStore
        from app.document_store import DocumentStore

        cls.main_module = main_module
        cls.original_document_store = main_module._document_store
        cls.original_auth_store = main_module._auth_store
        database_path = Path(cls.directory.name) / "auth.sqlite3"
        main_module._document_store = DocumentStore(database_path)
        main_module._auth_store = AuthStore(database_path)
        cls.client = TestClient(app)
        cls.origin = "http://localhost:5173"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        cls.main_module._document_store = cls.original_document_store
        cls.main_module._auth_store = cls.original_auth_store
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
