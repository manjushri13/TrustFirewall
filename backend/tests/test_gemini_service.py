import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.gemini_service import GeminiServiceError, generate_response


class GeminiServiceTests(unittest.TestCase):
    @patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=True)
    def test_sends_prompt_with_required_model(self) -> None:
        client = Mock()
        client.models.generate_content.return_value = SimpleNamespace(text=" Gemini reply ")

        result = generate_response("Summarize this.", client=client)

        self.assertEqual(result, "Gemini reply")
        client.models.generate_content.assert_called_once_with(
            model="gemini-3.6-flash",
            contents="Summarize this.",
        )

    @patch.dict(os.environ, {}, clear=True)
    def test_missing_api_key_fails_without_calling_sdk(self) -> None:
        with patch("app.gemini_service.genai.Client") as client_factory:
            with self.assertRaisesRegex(GeminiServiceError, "not configured"):
                generate_response("Hello")
        client_factory.assert_not_called()

    @patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=True)
    def test_sdk_error_is_wrapped_without_exposing_details(self) -> None:
        client = Mock()
        client.models.generate_content.side_effect = RuntimeError("secret transport detail")

        with self.assertRaisesRegex(GeminiServiceError, "request failed"):
            generate_response("Hello", client=client)

    @patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=True)
    def test_empty_response_fails_safely(self) -> None:
        client = Mock()
        client.models.generate_content.return_value = SimpleNamespace(text="  ")

        with self.assertRaisesRegex(GeminiServiceError, "empty response"):
            generate_response("Hello", client=client)

    @patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=True)
    def test_empty_prompt_is_rejected(self) -> None:
        client = Mock()

        with self.assertRaisesRegex(GeminiServiceError, "prompt must not be empty"):
            generate_response(" \t", client=client)
        client.models.generate_content.assert_not_called()
