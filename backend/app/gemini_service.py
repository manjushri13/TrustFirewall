from __future__ import annotations

import os
from typing import Any

from google import genai


MODEL_NAME = "gemini-3.6-flash"


class GeminiServiceError(RuntimeError):
    """Raised when Gemini cannot produce a usable response."""


def generate_response(prompt: str, *, client: Any | None = None) -> str:
    """Generate text from Gemini using the server-side API key.

    The optional client is intended for dependency injection in tests. Production
    calls create the official SDK client from GEMINI_API_KEY at request time.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise GeminiServiceError("GEMINI_API_KEY is not configured.")
    if not prompt.strip():
        raise GeminiServiceError("The Gemini prompt must not be empty.")

    sdk_client = client or genai.Client(api_key=api_key)
    try:
        response = sdk_client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
        )
    except Exception as error:
        raise GeminiServiceError("Gemini request failed.") from error

    text = getattr(response, "text", None)
    if not isinstance(text, str) or not text.strip():
        raise GeminiServiceError("Gemini returned an empty response.")
    return text.strip()
