"""
Tests for the LLM call chain detector.
"""
from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel_agent_core.analyzers.llm_callchain import analyze_llm_callchains


class LlmCallChainTests(unittest.TestCase):

    # ── Python detection ──────────────────────────────────────────────────────

    def test_detects_openai_chat_completion(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "chat.py").write_text(textwrap.dedent("""\
                import openai
                client = openai.OpenAI()
                response = client.chat.completions.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": "Hello"}],
                )
            """), encoding="utf-8")
            report = analyze_llm_callchains(root)

        self.assertGreaterEqual(len(report.call_sites), 1)
        openai_sites = [s for s in report.call_sites if "openai" in s.framework]
        self.assertGreater(len(openai_sites), 0)
        # A purely static call should not be classified as user input
        non_user_sites = [
            s for s in report.call_sites
            if s.input_classification in ("STATIC", "UNKNOWN")
        ]
        self.assertGreater(len(non_user_sites), 0)

    def test_detects_anthropic_messages_create(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "ai.py").write_text(textwrap.dedent("""\
                import anthropic
                client = anthropic.Anthropic()
                message = client.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    messages=[{"role": "user", "content": "Hello"}],
                )
            """), encoding="utf-8")
            report = analyze_llm_callchains(root)

        self.assertTrue(len(report.call_sites) >= 1)
        frameworks = {s.framework for s in report.call_sites}
        self.assertTrue(any("anthropic" in fw for fw in frameworks))

    def test_classifies_user_input_as_direct(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "handler.py").write_text(textwrap.dedent("""\
                import openai
                client = openai.OpenAI()
                def handle(req):
                    user_message = req.body["message"]
                    response = client.chat.completions.create(
                        model="gpt-4o",
                        messages=[{"role": "user", "content": user_message}],
                    )
                    return response
            """), encoding="utf-8")
            report = analyze_llm_callchains(root)

        direct = [s for s in report.call_sites if s.input_classification == "DIRECT_USER_INPUT"]
        self.assertGreater(len(direct), 0)
        self.assertEqual(report.direct_injection_surface, len(direct))

    def test_classifies_db_fetch_as_indirect(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "rag.py").write_text(textwrap.dedent("""\
                import openai
                client = openai.OpenAI()
                def rag_query(query_id: str):
                    docs = db.query("SELECT content FROM docs WHERE id = ?", query_id)
                    response = client.chat.completions.create(
                        model="gpt-4o",
                        messages=[{"role": "user", "content": docs[0]["content"]}],
                    )
                    return response
            """), encoding="utf-8")
            report = analyze_llm_callchains(root)

        indirect = [s for s in report.call_sites if s.input_classification == "INDIRECT_INPUT"]
        self.assertGreater(len(indirect), 0)

    def test_detects_langchain_invoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "chain.py").write_text(textwrap.dedent("""\
                from langchain_openai import ChatOpenAI
                from langchain.chains import LLMChain
                llm = ChatOpenAI(model="gpt-4o")
                result = llm.invoke("Translate this text")
            """), encoding="utf-8")
            report = analyze_llm_callchains(root)

        self.assertGreater(len(report.call_sites), 0)
        frameworks = {s.framework for s in report.call_sites}
        self.assertTrue(any("langchain" in fw or "openai" in fw for fw in frameworks))

    def test_no_llm_calls_empty_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "utils.py").write_text(
                "def add(a, b): return a + b", encoding="utf-8"
            )
            report = analyze_llm_callchains(root)

        self.assertEqual(len(report.call_sites), 0)
        self.assertEqual(report.direct_injection_surface, 0)
        self.assertIn("No LLM", report.summary)

    # ── JavaScript / TypeScript detection ─────────────────────────────────────

    def test_detects_openai_js_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "api.ts").write_text(textwrap.dedent("""\
                import OpenAI from 'openai';
                const client = new OpenAI();
                const response = await client.chat.completions.create({
                    model: 'gpt-4o',
                    messages: [{ role: 'user', content: 'Hello' }],
                });
            """), encoding="utf-8")
            report = analyze_llm_callchains(root)

        self.assertGreater(len(report.call_sites), 0)
        self.assertIn("openai", report.frameworks_detected)

    def test_detects_vercel_ai_sdk(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "route.ts").write_text(textwrap.dedent("""\
                import { streamText } from 'ai';
                import { openai } from '@ai-sdk/openai';
                export async function POST(req: Request) {
                    const { messages } = await req.json();
                    const result = streamText({
                        model: openai('gpt-4o'),
                        messages,
                    });
                    return result.toDataStreamResponse();
                }
            """), encoding="utf-8")
            report = analyze_llm_callchains(root)

        self.assertGreater(len(report.call_sites), 0)

    def test_js_direct_user_input_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "chat.ts").write_text(textwrap.dedent("""\
                import OpenAI from 'openai';
                const client = new OpenAI();
                export async function handler(req: Request) {
                    const { message } = await req.json();
                    const completion = await client.chat.completions.create({
                        model: 'gpt-4o',
                        messages: [{ role: 'user', content: message }],
                    });
                    return completion;
                }
            """), encoding="utf-8")
            report = analyze_llm_callchains(root)

        direct = [s for s in report.call_sites if s.input_classification == "DIRECT_USER_INPUT"]
        self.assertGreater(len(direct), 0)

    # ── Risk classification ────────────────────────────────────────────────────

    def test_risk_levels_consistent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "handler.py").write_text(textwrap.dedent("""\
                import openai
                client = openai.OpenAI()
                def handle(req):
                    user_msg = req.body["text"]
                    return client.chat.completions.create(
                        model="gpt-4o",
                        messages=[{"role": "user", "content": user_msg}],
                    )
            """), encoding="utf-8")
            report = analyze_llm_callchains(root)

        for site in report.call_sites:
            self.assertIn(site.risk_level, ["critical", "high", "medium", "low"])
            if site.input_classification == "DIRECT_USER_INPUT":
                self.assertEqual(site.risk_level, "critical")
            elif site.input_classification == "STATIC":
                self.assertEqual(site.risk_level, "low")

    def test_multiple_files_aggregated(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for i in range(3):
                (root / f"module{i}.py").write_text(textwrap.dedent(f"""\
                    import openai
                    client = openai.OpenAI()
                    def call_{i}():
                        return client.chat.completions.create(
                            model="gpt-4o",
                            messages=[{{"role": "user", "content": "query {i}"}}],
                        )
                """), encoding="utf-8")
            report = analyze_llm_callchains(root)

        self.assertGreaterEqual(len(report.call_sites), 3)
        self.assertGreaterEqual(report.total_files_scanned, 3)

    def test_raises_on_missing_path(self) -> None:
        with self.assertRaises(FileNotFoundError):
            analyze_llm_callchains("/nonexistent/repo/xyz")


if __name__ == "__main__":
    unittest.main()
