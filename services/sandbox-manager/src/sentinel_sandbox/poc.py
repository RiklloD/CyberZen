"""
Proof-of-Concept generator.

Converts a successful ExploitAttempt into:
  - A curl command (for engineers to run immediately)
  - A Python script (for the finding's PR body)
"""

from __future__ import annotations

from .models import ExploitAttempt


def build_curl_poc(attempt: ExploitAttempt) -> str:
    """
    Render the winning attempt as a curl one-liner.

    Example output:
        curl -X POST 'http://target/api/login' \\
          -H 'Content-Type: application/json' \\
          -d '{"username":"admin","password":"'"'"' OR 1=1--"}' \\
          -v
    """
    req = attempt.request
    parts = [f"curl -X {req.method} '{req.url}'"]

    for key, val in req.headers.items():
        if key.lower() == "user-agent" and "Sentinel" in val:
            continue  # Don't expose scanner identity in PoC
        parts.append(f"  -H '{key}: {val}'")

    if req.body:
        # Escape single quotes for shell safety
        escaped = req.body.replace("'", "'\\''")
        parts.append(f"  -d '{escaped}'")

    parts.append("  -v")
    return " \\\n".join(parts)


def build_python_poc(attempt: ExploitAttempt) -> str:
    """
    Render the winning attempt as a minimal Python/httpx script
    that an engineer can run to reproduce the finding.
    """
    req = attempt.request
    resp = attempt.response

    lines = [
        '"""',
        "Sentinel PoC — Exploit Reproduction Script",
        f"Payload: {attempt.payload_label}",
        f"Category: {attempt.category.value}",
        '"""',
        "",
        "import httpx",
        "",
        "TARGET = " + repr(req.url),
        "METHOD = " + repr(req.method),
        "HEADERS = " + repr(req.headers),
    ]

    if req.body:
        lines.append("BODY = " + repr(req.body))
    else:
        lines.append("BODY = None")

    lines += [
        "",
        "# Expected success indicators",
        "INDICATORS = " + repr(attempt.success_indicators),
        "",
        "response = httpx.request(",
        "    method=METHOD,",
        "    url=TARGET,",
        "    headers=HEADERS,",
        "    content=BODY.encode() if BODY else None,",
        "    verify=False,",
        "    follow_redirects=True,",
        ")",
        "",
        "print(f'Status: {response.status_code}')",
        "print(f'Body (first 500 chars):')",
        "print(response.text[:500])",
        "",
        "matched = [i for i in INDICATORS if i.lower() in response.text.lower()]",
        "if matched:",
        "    print(f'\\n✓ SUCCESS — matched indicators: {matched}')",
        "else:",
        "    print('\\n✗ No indicators matched — verify manually')",
    ]

    if resp:
        lines += [
            "",
            "# Original sandbox response for reference:",
            f"# Status: {resp.status_code}",
            f"# Elapsed: {resp.elapsed_ms:.0f}ms",
            f"# Body snippet: {resp.body_snippet[:200]!r}",
        ]

    return "\n".join(lines)
