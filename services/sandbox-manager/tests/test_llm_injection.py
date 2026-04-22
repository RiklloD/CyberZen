"""
Tests for the LLM Injection module.

Covers:
  - vuln_class routing (can_handle)
  - Attempt generation: correct count, structure, body shapes, endpoint paths
  - Request body is valid JSON for all three formats
  - Success indicators are non-empty and contain canary strings
  - Module metadata (name, category, handles list)
  - Integration with executor module registry
"""

import json
import unittest

from sentinel_sandbox.exploits.llm_injection import (
    LlmInjectionModule,
    _AI_PATHS,
    _BODY_BUILDERS,
    _PAYLOADS,
)
from sentinel_sandbox.models import (
    ExploitCategory,
    SandboxMode,
    ValidationRequest,
)


class TestLlmInjectionModule(unittest.TestCase):

    def setUp(self):
        self.module = LlmInjectionModule()
        self.req = ValidationRequest(
            finding_id="test-finding-001",
            repository_full_name="acme/ai-service",
            vuln_class="prompt_injection",
            severity="high",
            target_base_url="http://localhost:8080",
        )

    # ── Module metadata ───────────────────────────────────────────────────────

    def test_name(self):
        self.assertEqual(self.module.name, "llm_injection")

    def test_category(self):
        self.assertEqual(self.module.category, ExploitCategory.LLM_INJECTION)

    def test_handles_list_is_non_empty(self):
        self.assertGreater(len(self.module.handles), 0)

    # ── can_handle routing ────────────────────────────────────────────────────

    def test_handles_prompt_injection(self):
        self.assertTrue(self.module.can_handle("prompt_injection"))

    def test_handles_llm_injection(self):
        self.assertTrue(self.module.can_handle("llm_injection"))

    def test_handles_ai_injection(self):
        self.assertTrue(self.module.can_handle("ai_injection"))

    def test_handles_indirect_injection(self):
        self.assertTrue(self.module.can_handle("indirect_injection"))

    def test_handles_jailbreak(self):
        self.assertTrue(self.module.can_handle("jailbreak"))

    def test_handles_llm_attack(self):
        self.assertTrue(self.module.can_handle("llm_attack"))

    def test_does_not_handle_sql_injection(self):
        self.assertFalse(self.module.can_handle("sql_injection"))

    def test_does_not_handle_xss(self):
        self.assertFalse(self.module.can_handle("xss"))

    def test_does_not_handle_path_traversal(self):
        self.assertFalse(self.module.can_handle("path_traversal"))

    def test_handles_case_insensitive(self):
        self.assertTrue(self.module.can_handle("PROMPT_INJECTION"))
        self.assertTrue(self.module.can_handle("Jailbreak"))

    # ── Attempt generation ────────────────────────────────────────────────────

    def test_generates_attempts(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        self.assertGreater(len(attempts), 0)

    def test_attempt_count_equals_payloads_times_paths_times_formats(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        expected = len(_PAYLOADS) * len(_AI_PATHS) * len(_BODY_BUILDERS)
        self.assertEqual(len(attempts), expected)

    def test_all_attempts_are_post(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        for a in attempts:
            self.assertEqual(a.request.method, "POST")

    def test_all_attempts_have_json_content_type(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        for a in attempts:
            ct = a.request.headers.get("Content-Type", "")
            self.assertIn("application/json", ct)

    def test_all_attempts_have_non_empty_body(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        for a in attempts:
            self.assertIsNotNone(a.request.body)
            self.assertGreater(len(a.request.body or ""), 0)

    def test_all_bodies_are_valid_json(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        for a in attempts:
            try:
                json.loads(a.request.body or "")
            except json.JSONDecodeError:
                self.fail(f"Body is not valid JSON for attempt {a.payload_label}")

    def test_all_attempts_have_success_indicators(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        for a in attempts:
            self.assertGreater(len(a.success_indicators), 0,
                               f"No success indicators for {a.payload_label}")

    def test_all_attempts_category_is_llm_injection(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        for a in attempts:
            self.assertEqual(a.category, ExploitCategory.LLM_INJECTION)

    def test_timeout_is_generous_for_llm_inference(self):
        """LLM endpoints are slower than HTTP probes — timeout must be >= 10s."""
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        for a in attempts:
            self.assertGreaterEqual(a.request.timeout_seconds, 10.0)

    # ── Endpoint coverage ─────────────────────────────────────────────────────

    def test_covers_openai_compatible_endpoint(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        urls = [a.request.url for a in attempts]
        self.assertTrue(any("/v1/chat/completions" in u for u in urls))

    def test_covers_api_chat_endpoint(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        urls = [a.request.url for a in attempts]
        self.assertTrue(any("/api/chat" in u for u in urls))

    def test_covers_ollama_generate_endpoint(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        urls = [a.request.url for a in attempts]
        self.assertTrue(any("/api/generate" in u for u in urls))

    # ── Body format coverage ──────────────────────────────────────────────────

    def test_openai_format_has_messages_key(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        openai_bodies = [
            json.loads(a.request.body or "{}")
            for a in attempts
            if "openai_fmt" in a.payload_label
        ]
        self.assertGreater(len(openai_bodies), 0)
        for body in openai_bodies:
            self.assertIn("messages", body)

    def test_simple_format_has_message_key(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        simple_bodies = [
            json.loads(a.request.body or "{}")
            for a in attempts
            if "simple_fmt" in a.payload_label
        ]
        self.assertGreater(len(simple_bodies), 0)
        for body in simple_bodies:
            self.assertIn("message", body)

    def test_generic_format_has_prompt_key(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        generic_bodies = [
            json.loads(a.request.body or "{}")
            for a in attempts
            if "generic_fmt" in a.payload_label
        ]
        self.assertGreater(len(generic_bodies), 0)
        for body in generic_bodies:
            self.assertIn("prompt", body)

    # ── Canary indicators ─────────────────────────────────────────────────────

    def test_canary_direct_indicator_present(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        canary_attempts = [a for a in attempts if "canary_direct" in a.payload_label]
        self.assertGreater(len(canary_attempts), 0)
        for a in canary_attempts:
            self.assertIn("sentinel_canary_4829", a.success_indicators)

    def test_canary_role_switch_indicator_present(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        canary_attempts = [a for a in attempts if "canary_role_switch" in a.payload_label]
        self.assertGreater(len(canary_attempts), 0)
        for a in canary_attempts:
            self.assertIn("sentinel_canary_7163", a.success_indicators)

    def test_tool_injection_indicator_present(self):
        attempts = self.module.generate_attempts(self.req, "http://localhost:8080")
        tool_attempts = [a for a in attempts if "tool_result_injection" in a.payload_label]
        self.assertGreater(len(tool_attempts), 0)
        for a in tool_attempts:
            self.assertIn("tool_injected_8521", a.success_indicators)

    # ── Integration: executor module registry ─────────────────────────────────

    def test_module_is_registered_in_executor(self):
        from sentinel_sandbox.executor import _MODULES
        module_types = [type(m).__name__ for m in _MODULES]
        self.assertIn("LlmInjectionModule", module_types)

    def test_executor_routes_prompt_injection_to_llm_module(self):
        """Ensure at least one module in _MODULES handles prompt_injection."""
        from sentinel_sandbox.executor import _MODULES
        handled = any(m.can_handle("prompt_injection") for m in _MODULES)
        self.assertTrue(handled)


if __name__ == "__main__":
    unittest.main()
