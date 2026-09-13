"""The AI provider abstraction: the Anthropic implementation over the choke point."""

import asyncio

import pytest

from scanner.ai.provider import AnthropicProvider


class _FakeResp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = str(payload)

    def json(self):
        return self._payload


class _FakeHttp:
    """Records the single POST the provider makes and returns a canned body."""

    def __init__(self, payload, status_code=200):
        self._resp = _FakeResp(payload, status_code)
        self.calls = []

    async def post(self, url, *, headers=None, json=None, **kwargs):
        self.calls.append({"url": url, "headers": headers or {}, "json": json or {}})
        return self._resp


def _run(coro):
    return asyncio.run(coro)


def test_posts_to_messages_api_and_parses_text():
    http = _FakeHttp({"content": [{"type": "text", "text": "  remediate like so  "}]})
    provider = AnthropicProvider(http, api_key="sk-test", model="claude-sonnet-5")
    out = _run(provider.complete(system="be brief", user="explain finding X", max_tokens=200))

    assert out == "remediate like so"  # trimmed
    call = http.calls[0]
    assert call["url"] == "https://api.anthropic.com/v1/messages"
    assert call["headers"]["x-api-key"] == "sk-test"
    assert call["headers"]["anthropic-version"]
    assert call["json"]["model"] == "claude-sonnet-5"
    assert call["json"]["max_tokens"] == 200
    assert call["json"]["system"] == "be brief"
    assert call["json"]["messages"] == [{"role": "user", "content": "explain finding X"}]


def test_raises_on_api_error_status():
    http = _FakeHttp({"error": {"message": "bad"}}, status_code=401)
    provider = AnthropicProvider(http, api_key="sk-test", model="claude-sonnet-5")
    with pytest.raises(RuntimeError):
        _run(provider.complete(system="s", user="u", max_tokens=10))
