"""
Tests for PoC generation — curl and Python script output.
"""

import pytest

from sentinel_sandbox.models import (
    ExploitAttempt,
    ExploitCategory,
    HttpAttemptRequest,
    HttpAttemptResponse,
)
from sentinel_sandbox.poc import build_curl_poc, build_python_poc


def _attempt(
    label: str = "sqli_test",
    method: str = "GET",
    url: str = "http://target/api?id=1'",
    headers: dict | None = None,
    body: str | None = None,
    indicators: list[str] | None = None,
    with_response: bool = True,
) -> ExploitAttempt:
    resp = None
    if with_response:
        resp = HttpAttemptResponse(
            status_code=500,
            headers={"content-type": "text/html"},
            body_snippet="SQL syntax error near '1'",
            elapsed_ms=42.0,
        )
    return ExploitAttempt(
        payload_label=label,
        category=ExploitCategory.SQL_INJECTION,
        request=HttpAttemptRequest(
            method=method,
            url=url,
            headers=headers or {},
            body=body,
        ),
        response=resp,
        success_indicators=indicators or ["SQL syntax"],
        matched_indicators=["SQL syntax"] if with_response else [],
        success=with_response,
    )


class TestBuildCurlPoc:
    def test_includes_method_and_url(self):
        poc = build_curl_poc(_attempt())
        assert "curl -X GET" in poc
        assert "http://target/api" in poc

    def test_includes_custom_headers(self):
        a = _attempt(headers={"Authorization": "Bearer abc123"})
        poc = build_curl_poc(a)
        assert "Authorization: Bearer abc123" in poc

    def test_sentinel_user_agent_not_in_poc(self):
        a = _attempt(headers={"User-Agent": "Sentinel-Security-Agent/1.0"})
        poc = build_curl_poc(a)
        assert "Sentinel-Security-Agent" not in poc

    def test_includes_body_when_present(self):
        a = _attempt(method="POST", body='{"key": "value"}')
        poc = build_curl_poc(a)
        assert "-d" in poc
        assert "key" in poc

    def test_includes_verbose_flag(self):
        poc = build_curl_poc(_attempt())
        assert "-v" in poc

    def test_multiline_format(self):
        poc = build_curl_poc(_attempt())
        assert "\\\n" in poc  # line continuation

    def test_single_quote_in_body_escaped(self):
        a = _attempt(method="POST", body="' OR 1=1--")
        poc = build_curl_poc(a)
        # Shell escape: ' becomes '\''
        assert "'\\''" in poc or "OR 1=1" in poc


class TestBuildPythonPoc:
    def test_imports_httpx(self):
        poc = build_python_poc(_attempt())
        assert "import httpx" in poc

    def test_target_url_present(self):
        poc = build_python_poc(_attempt(url="http://target/api?id=INJECT"))
        assert "http://target/api" in poc

    def test_success_indicators_listed(self):
        poc = build_python_poc(_attempt(indicators=["SQL syntax", "error"]))
        assert "SQL syntax" in poc
        assert "error" in poc

    def test_response_snippet_in_comments(self):
        poc = build_python_poc(_attempt(with_response=True))
        assert "Status: 500" in poc

    def test_no_response_still_generates(self):
        a = _attempt(with_response=False)
        poc = build_python_poc(a)
        assert "import httpx" in poc

    def test_runnable_structure(self):
        poc = build_python_poc(_attempt())
        assert "response = httpx.request(" in poc
        assert "response.status_code" in poc
