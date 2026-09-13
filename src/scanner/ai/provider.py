"""Provider abstraction for the AI advisor: one generic 'ask the model' interface.

The rest of the advisor depends only on the :class:`Provider` protocol, so the
concrete AI service is swappable (decisions.md D19). v1 ships one implementation,
:class:`AnthropicProvider`, which talks to the Anthropic Messages API **through
the shared HTTP client** — so the request is subject to the same egress gate as
every other outbound call (``api.anthropic.com`` is allowlisted, contract §9) and
no private connection is opened.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"


class Provider(ABC):
    """Minimal interface: given a system instruction and a user message, return
    the model's text reply. Implementations must not do anything but call out to
    their service; the advisor owns all prompt construction and finding logic."""

    @abstractmethod
    async def complete(self, *, system: str, user: str, max_tokens: int) -> str:
        ...


class AnthropicProvider(Provider):
    def __init__(self, http, *, api_key: str, model: str) -> None:
        self._http = http
        self._api_key = api_key
        self._model = model

    async def complete(self, *, system: str, user: str, max_tokens: int) -> str:
        resp = await self._http.post(
            _ANTHROPIC_URL,
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": _ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
            json={
                "model": self._model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        status = getattr(resp, "status_code", 0)
        if status >= 400:
            body = (getattr(resp, "text", "") or "")[:200]
            raise RuntimeError(f"Anthropic API returned {status}: {body}")
        data = resp.json()
        return _extract_text(data)


def _extract_text(data: dict) -> str:
    """Pull the assistant text out of a Messages API response, tolerating shape
    drift. Raises if there is no text block to report."""
    blocks = data.get("content") if isinstance(data, dict) else None
    if isinstance(blocks, list):
        parts = [b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type", "text") == "text"]
        joined = "".join(parts).strip()
        if joined:
            return joined
    raise RuntimeError("Anthropic API response contained no text content.")
