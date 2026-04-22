"""
Tests for agentic_workflow.py — Agentic Workflow Security Scanner
"""

import unittest
import tempfile
from pathlib import Path

from sentinel_agent_core.analyzers.agentic_workflow import (
    analyze_agentic_workflows,
    AgentWorkflowReport,
    UNBOUNDED_LOOP,
    PRIVILEGE_ESCALATION,
    DATA_EXFILTRATION_CHAIN,
    TOOL_RESULT_INJECTION,
    MEMORY_POISONING,
    INSECURE_INTER_AGENT_COMM,
    UNVALIDATED_TOOL_OUTPUT,
)


# ── Test helpers ───────────────────────────────────────────────────────────────

def _make_repo(files: dict[str, str]) -> Path:
    """Creates a temp directory with the given filename → content mapping."""
    tmp = Path(tempfile.mkdtemp())
    for fname, content in files.items():
        fpath = tmp / fname
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content)
    return tmp


def _scan(files: dict[str, str]) -> AgentWorkflowReport:
    root = _make_repo(files)
    return analyze_agentic_workflows(str(root))


def _vuln_classes(report: AgentWorkflowReport) -> list[str]:
    return [f.vuln_class for f in report.findings]


# ── Clean-repo baseline ────────────────────────────────────────────────────────

class TestCleanRepo(unittest.TestCase):
    def test_empty_repo(self):
        report = _scan({})
        self.assertEqual(report.findings, [])
        self.assertEqual(report.total_files_scanned, 0)

    def test_no_agentic_code(self):
        report = _scan({"app.py": "print('hello')\n"})
        self.assertEqual(report.findings, [])

    def test_summary_clean(self):
        report = _scan({})
        self.assertIn("No agentic", report.summary)


# ── LangChain ─────────────────────────────────────────────────────────────────

class TestLangChain(unittest.TestCase):
    def test_agent_executor_without_max_iterations_flagged(self):
        code = "from langchain.agents import AgentExecutor\nagent = AgentExecutor(agent=a, tools=t)\n"
        report = _scan({"agent.py": code})
        self.assertIn(UNBOUNDED_LOOP, _vuln_classes(report))

    def test_agent_executor_with_max_iterations_clean(self):
        code = (
            "from langchain.agents import AgentExecutor\n"
            "agent = AgentExecutor(agent=a, tools=t, max_iterations=10)\n"
        )
        report = _scan({"agent.py": code})
        self.assertNotIn(UNBOUNDED_LOOP, _vuln_classes(report))

    def test_create_react_agent_without_max_iterations_flagged(self):
        code = "from langchain.agents import create_react_agent\nagent = create_react_agent(llm, tools, prompt)\n"
        report = _scan({"agent.py": code})
        self.assertIn(UNBOUNDED_LOOP, _vuln_classes(report))

    def test_finding_has_correct_severity(self):
        code = "from langchain.agents import AgentExecutor\nagent = AgentExecutor(agent=a, tools=t)\n"
        report = _scan({"agent.py": code})
        unbounded = [f for f in report.findings if f.vuln_class == UNBOUNDED_LOOP]
        self.assertEqual(unbounded[0].severity, "high")

    def test_finding_references_correct_file(self):
        code = "from langchain.agents import AgentExecutor\nagent = AgentExecutor(agent=a, tools=t)\n"
        report = _scan({"my_agent.py": code})
        self.assertTrue(any("my_agent.py" in f.file for f in report.findings))


# ── CrewAI ────────────────────────────────────────────────────────────────────

class TestCrewAI(unittest.TestCase):
    def test_hierarchical_process_flagged(self):
        code = (
            "from crewai import Crew, Process\n"
            "crew = Crew(agents=[a], tasks=[t], process=Process.hierarchical)\n"
        )
        report = _scan({"crew.py": code})
        self.assertIn(PRIVILEGE_ESCALATION, _vuln_classes(report))

    def test_allow_delegation_true_flagged(self):
        code = (
            "from crewai import Agent\n"
            "researcher = Agent(role='Researcher', allow_delegation=True, tools=[search])\n"
        )
        report = _scan({"agents.py": code})
        self.assertIn(PRIVILEGE_ESCALATION, _vuln_classes(report))

    def test_sequential_process_clean(self):
        code = (
            "from crewai import Crew, Process\n"
            "crew = Crew(agents=[a], tasks=[t], process=Process.sequential)\n"
        )
        report = _scan({"crew.py": code})
        self.assertNotIn(PRIVILEGE_ESCALATION, _vuln_classes(report))

    def test_privilege_escalation_severity_critical(self):
        code = (
            "from crewai import Crew, Process\n"
            "crew = Crew(agents=[a], tasks=[t], process=Process.hierarchical)\n"
        )
        report = _scan({"crew.py": code})
        escalation = [f for f in report.findings if f.vuln_class == PRIVILEGE_ESCALATION]
        self.assertEqual(escalation[0].severity, "critical")


# ── AutoGen ───────────────────────────────────────────────────────────────────

class TestAutoGen(unittest.TestCase):
    def test_groupchat_flagged_as_insecure_inter_agent(self):
        code = (
            "from autogen import AssistantAgent, GroupChat\n"
            "groupchat = GroupChat(agents=[a1, a2], messages=[], max_round=10)\n"
        )
        report = _scan({"multi_agent.py": code})
        self.assertIn(INSECURE_INTER_AGENT_COMM, _vuln_classes(report))

    def test_code_execution_enabled_flagged(self):
        code = (
            "from autogen import UserProxyAgent\n"
            "proxy = UserProxyAgent('user', code_execution_config={'work_dir': '/tmp'})\n"
        )
        report = _scan({"proxy.py": code})
        self.assertIn(PRIVILEGE_ESCALATION, _vuln_classes(report))

    def test_conversable_agent_alone_no_finding(self):
        code = (
            "from autogen import ConversableAgent\n"
            "a = ConversableAgent('bot', code_execution_config=False)\n"
        )
        report = _scan({"agent.py": code})
        # code_execution_config=False should NOT flag privilege escalation
        priv = [f for f in report.findings if f.vuln_class == PRIVILEGE_ESCALATION]
        self.assertEqual(priv, [])


# ── LlamaIndex ────────────────────────────────────────────────────────────────

class TestLlamaIndex(unittest.TestCase):
    def test_agent_runner_without_max_steps_flagged(self):
        code = (
            "from llama_index.agent.openai import OpenAIAgent\n"
            "agent = AgentRunner.from_llm(tools=tools, llm=llm)\n"
        )
        report = _scan({"agent.py": code})
        self.assertIn(UNBOUNDED_LOOP, _vuln_classes(report))

    def test_react_agent_with_max_steps_clean(self):
        code = (
            "from llama_index.core.agent import ReActAgent\n"
            "agent = ReActAgent.from_tools(tools, max_steps=5)\n"
        )
        report = _scan({"agent.py": code})
        self.assertNotIn(UNBOUNDED_LOOP, _vuln_classes(report))


# ── Memory poisoning ──────────────────────────────────────────────────────────

class TestMemoryPoisoning(unittest.TestCase):
    def test_vector_store_add_documents_flagged(self):
        code = (
            "from langchain.vectorstores import Chroma\n"
            "vectorstore.add_documents(user_documents)\n"
        )
        report = _scan({"memory.py": code})
        self.assertIn(MEMORY_POISONING, _vuln_classes(report))

    def test_save_context_flagged(self):
        code = (
            "from langchain.memory import ConversationBufferMemory\n"
            "memory.save_context({'input': user_input}, {'output': response})\n"
        )
        report = _scan({"memory.py": code})
        self.assertIn(MEMORY_POISONING, _vuln_classes(report))

    def test_vector_store_read_only_clean(self):
        code = (
            "from langchain.vectorstores import Chroma\n"
            "results = vectorstore.similarity_search(query)\n"
        )
        report = _scan({"memory.py": code})
        self.assertNotIn(MEMORY_POISONING, _vuln_classes(report))


# ── Data exfiltration chain ───────────────────────────────────────────────────

class TestDataExfiltrationChain(unittest.TestCase):
    def test_read_file_plus_send_email_flagged(self):
        code = (
            "from langchain.agents import AgentExecutor\n"
            "tools = [read_file_tool, send_email_tool]\n"
            "agent = AgentExecutor(agent=a, tools=tools, max_iterations=5)\n"
            "\ndef read_file(path): return open(path).read()\n"
            "def send_email(to, body): return sendgrid.send(to, body)\n"
        )
        report = _scan({"agent.py": code})
        self.assertIn(DATA_EXFILTRATION_CHAIN, _vuln_classes(report))

    def test_read_only_tools_no_exfil_finding(self):
        code = (
            "from langchain.agents import AgentExecutor\n"
            "tools = [search_tool, calculator_tool]\n"
            "agent = AgentExecutor(agent=a, tools=tools, max_iterations=5)\n"
            "\ndef search(q): return requests.get(f'https://search.api/{q}').json()\n"
        )
        report = _scan({"agent.py": code})
        self.assertNotIn(DATA_EXFILTRATION_CHAIN, _vuln_classes(report))


# ── Vercel AI SDK (JS) ────────────────────────────────────────────────────────

class TestVercelAiSdk(unittest.TestCase):
    def test_generate_text_with_tools_no_maxsteps_flagged(self):
        code = (
            "import { generateText } from 'ai';\n"
            "const result = await generateText({ model, tools: { search, read }, prompt });\n"
        )
        report = _scan({"agent.ts": code})
        self.assertIn(UNBOUNDED_LOOP, _vuln_classes(report))

    def test_generate_text_with_maxsteps_clean(self):
        code = (
            "import { generateText } from 'ai';\n"
            "const result = await generateText({ model, tools: { search }, prompt, maxSteps: 5 });\n"
        )
        report = _scan({"agent.ts": code})
        self.assertNotIn(UNBOUNDED_LOOP, _vuln_classes(report))

    def test_tool_execute_without_return_type_flagged(self):
        code = (
            "import { generateText, tool } from 'ai';\n"
            "const t = tool({ description: '...', parameters: schema, execute: async (args) => fetch(args.url) });\n"
        )
        report = _scan({"tools.ts": code})
        self.assertIn(UNVALIDATED_TOOL_OUTPUT, _vuln_classes(report))


# ── Severity and counter tallying ─────────────────────────────────────────────

class TestCounters(unittest.TestCase):
    def test_critical_counter_increments(self):
        code = (
            "from crewai import Crew, Process\n"
            "crew = Crew(agents=[a], tasks=[t], process=Process.hierarchical)\n"
        )
        report = _scan({"crew.py": code})
        self.assertGreater(report.critical_count, 0)

    def test_high_counter_increments(self):
        code = "from langchain.agents import AgentExecutor\nagent = AgentExecutor(agent=a, tools=t)\n"
        report = _scan({"agent.py": code})
        self.assertGreater(report.high_count, 0)

    def test_frameworks_detected_populated(self):
        code = "from langchain.agents import AgentExecutor\nagent = AgentExecutor(agent=a, tools=t)\n"
        report = _scan({"agent.py": code})
        self.assertIn("langchain", report.frameworks_detected)

    def test_summary_includes_counts(self):
        code = "from langchain.agents import AgentExecutor\nagent = AgentExecutor(agent=a, tools=t)\n"
        report = _scan({"agent.py": code})
        self.assertIn("1", report.summary)

    def test_file_not_found_raises(self):
        with self.assertRaises(FileNotFoundError):
            analyze_agentic_workflows("/nonexistent/path/repo")


# ── Remediation guidance ──────────────────────────────────────────────────────

class TestRemediation(unittest.TestCase):
    def test_unbounded_loop_remediation_mentions_max_iterations(self):
        code = "from langchain.agents import AgentExecutor\nagent = AgentExecutor(agent=a, tools=t)\n"
        report = _scan({"agent.py": code})
        unbounded = [f for f in report.findings if f.vuln_class == UNBOUNDED_LOOP]
        self.assertIn("max_iterations", unbounded[0].remediation)

    def test_privilege_escalation_remediation_mentions_allow_delegation(self):
        code = (
            "from crewai import Agent\nresearcher = Agent(role='R', allow_delegation=True, tools=[t])\n"
        )
        report = _scan({"agents.py": code})
        priv = [f for f in report.findings if f.vuln_class == PRIVILEGE_ESCALATION]
        self.assertIn("allow_delegation", priv[0].remediation)

    def test_memory_poisoning_remediation_mentions_sanitise(self):
        code = "vectorstore.add_documents(user_input)\n"
        report = _scan({"mem.py": code})
        mem = [f for f in report.findings if f.vuln_class == MEMORY_POISONING]
        self.assertIn("Sanitise", mem[0].remediation)


if __name__ == "__main__":
    unittest.main()
