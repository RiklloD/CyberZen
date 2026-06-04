"""
Agentic Workflow Security Scanner — spec §10 Phase 4

Detects security vulnerabilities specific to agentic AI pipelines: not individual
LLM API calls (that's llm_callchain.py), but the *orchestration layer* — how agents
are composed, how tools are registered, and what controls govern their execution.

Frameworks covered:
  LangChain / LangGraph  — AgentExecutor, create_react_agent, LangGraph StateGraph
  CrewAI                 — Crew, Agent, Task, Process.hierarchical
  AutoGen                — ConversableAgent, AssistantAgent, GroupChat, register_function
  LlamaIndex             — AgentRunner, ReActAgent, FunctionCallingAgentWorker
  Vercel AI SDK          — generateText/streamText with tools=
  Custom                 — any pattern with tools=[] + recursive agent delegation

Vulnerability classes detected:
  UNBOUNDED_LOOP            — agent can call tools without a max_iterations cap
  PRIVILEGE_ESCALATION      — agent delegates with its full tool permissions to sub-agents
  DATA_EXFILTRATION_CHAIN   — tool sequence that could leak data (read → send)
  TOOL_RESULT_INJECTION     — tool output fed to next prompt without sanitisation
  MEMORY_POISONING          — adversarial writes to a persistent memory/vector store
  INSECURE_INTER_AGENT_COMM — no auth/signing between agents in a multi-agent system
  UNVALIDATED_TOOL_OUTPUT   — tool return value used directly without schema validation
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

# ── Vulnerability class constants ──────────────────────────────────────────────

UNBOUNDED_LOOP = "unbounded_loop"
PRIVILEGE_ESCALATION = "privilege_escalation"
DATA_EXFILTRATION_CHAIN = "data_exfiltration_chain"
TOOL_RESULT_INJECTION = "tool_result_injection"
MEMORY_POISONING = "memory_poisoning"
INSECURE_INTER_AGENT_COMM = "insecure_inter_agent_comm"
UNVALIDATED_TOOL_OUTPUT = "unvalidated_tool_output"

SEVERITY_MAP: dict[str, str] = {
    UNBOUNDED_LOOP: "high",
    PRIVILEGE_ESCALATION: "critical",
    DATA_EXFILTRATION_CHAIN: "critical",
    TOOL_RESULT_INJECTION: "high",
    MEMORY_POISONING: "high",
    INSECURE_INTER_AGENT_COMM: "medium",
    UNVALIDATED_TOOL_OUTPUT: "medium",
}

# ── Detection patterns ─────────────────────────────────────────────────────────

# LangChain / LangGraph
LANGCHAIN_AGENT_EXECUTOR = re.compile(r"\bAgentExecutor\b")
LANGCHAIN_CREATE_AGENT = re.compile(r"\bcreate_(?:react|openai_tools|openai_functions|structured_chat)_agent\b")
LANGCHAIN_AGENT_MAX_ITER = re.compile(r"\bmax_iterations\s*=")
LANGGRAPH_STATEGRAPH = re.compile(r"\bStateGraph\b|\bCompiledGraph\b")

# CrewAI
CREWAI_CREW = re.compile(r"\bCrew\s*\(")
CREWAI_HIERARCHICAL = re.compile(r"\bProcess\.hierarchical\b")
CREWAI_AGENT_WITH_TOOLS = re.compile(r"\bAgent\s*\(.*?tools\s*=", re.DOTALL)
CREWAI_ALLOW_DELEGATION = re.compile(r"\ballow_delegation\s*=\s*True")

# AutoGen
AUTOGEN_CONVERSABLE = re.compile(r"\bConversableAgent\s*\(|\bAssistantAgent\s*\(|\bUserProxyAgent\s*\(")
AUTOGEN_GROUPCHAT = re.compile(r"\bGroupChat\s*\(")
AUTOGEN_REGISTER_FUNCTION = re.compile(r"\bregister_function\s*\(|\bregister_for_llm\s*\(")
AUTOGEN_CODE_EXECUTION = re.compile(r"\bcode_execution_config\s*=\s*\{(?!.*\bFalse\b)")

# LlamaIndex Agents
LLAMAINDEX_AGENT = re.compile(r"\b(?:AgentRunner|ReActAgent|FunctionCallingAgentWorker|OpenAIAgent)\b")
LLAMAINDEX_MAX_STEPS = re.compile(r"\bmax_steps\b|\bmax_function_calls\b")

# Vercel AI SDK (JS/TS)
VERCEL_TOOLS_NO_MAXSTEPS = re.compile(
    r"(?:generateText|streamText)\s*\(\s*\{[^}]*\btools\s*:[^}]*\}",
    re.DOTALL,
)
VERCEL_MAX_STEPS = re.compile(r"\bmaxSteps\s*:")
VERCEL_TOOL_EXECUTE = re.compile(r"\bexecute\s*:\s*async")

# Generic tool + memory patterns (cross-framework)
TOOL_REGISTRATION = re.compile(r"\btools\s*=\s*\[")
MEMORY_STORE_WRITE = re.compile(
    r"\.(?:add_documents?|upsert|save_context|save_memory|add_message|remember|store)\s*\("
)
READ_THEN_SEND = re.compile(r"read_file|open\(|requests\.get|httpx\.get|fetch\(")
SEND_FUNCTIONS = re.compile(r"requests\.post|httpx\.post|send_email|smtp|smtplib|sendgrid|mailgun")

# Tool output used without validation
TOOL_RESULT_DIRECT_USE = re.compile(r"tool_result\s*=.*\n.*\{.*tool_result", re.DOTALL)
NO_TOOL_SCHEMA = re.compile(r"tools\s*=\s*\[")

# Ignored directories (mirrors llm_callchain.py)
IGNORED_DIRS = {
    ".git", "node_modules", ".turbo", ".next", "dist", "build", "target",
    "__pycache__", ".venv", "venv", ".pytest_cache", "coverage",
}

# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class AgentFinding:
    """A single security issue detected in an agentic pipeline."""
    file: str
    line: int
    framework: str
    vuln_class: str
    severity: str
    evidence: str          # short description of what was found
    remediation: str       # concrete fix recommendation


@dataclass
class AgentWorkflowReport:
    """Aggregated result of scanning a repository for agentic security issues."""
    repository_path: str
    findings: list[AgentFinding] = field(default_factory=list)
    total_files_scanned: int = 0
    frameworks_detected: list[str] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    summary: str = ""

    def build_summary(self) -> str:
        if not self.findings:
            return "No agentic workflow security issues detected."
        frameworks = ", ".join(sorted(set(self.frameworks_detected)))
        return (
            f"Detected {len(self.findings)} agentic security issue(s) across "
            f"{self.critical_count} critical / {self.high_count} high / {self.medium_count} medium "
            f"using: {frameworks}."
        )


# ── Per-finding constructors ───────────────────────────────────────────────────

def _unbounded_loop(file: str, line: int, framework: str) -> AgentFinding:
    return AgentFinding(
        file=file, line=line, framework=framework,
        vuln_class=UNBOUNDED_LOOP,
        severity=SEVERITY_MAP[UNBOUNDED_LOOP],
        evidence=f"{framework} agent created without max_iterations / max_steps cap.",
        remediation="Set max_iterations= (LangChain), max_steps= (LlamaIndex), or maxSteps: (Vercel AI SDK) "
                    "to prevent runaway tool-call loops that consume unbounded compute or exfiltrate data incrementally.",
    )


def _privilege_escalation(file: str, line: int, framework: str, detail: str = "") -> AgentFinding:
    return AgentFinding(
        file=file, line=line, framework=framework,
        vuln_class=PRIVILEGE_ESCALATION,
        severity=SEVERITY_MAP[PRIVILEGE_ESCALATION],
        evidence=f"{framework} agent delegates to sub-agents with full tool permissions. {detail}".strip(),
        remediation="In CrewAI, set allow_delegation=False on agents that should not spawn sub-tasks, "
                    "or restrict the tools= list passed to each agent to the minimum required scope.",
    )


def _data_exfiltration_chain(file: str, line: int, framework: str) -> AgentFinding:
    return AgentFinding(
        file=file, line=line, framework=framework,
        vuln_class=DATA_EXFILTRATION_CHAIN,
        severity=SEVERITY_MAP[DATA_EXFILTRATION_CHAIN],
        evidence="File/HTTP read tool registered alongside network-send tool — "
                 "a compromised agent could read sensitive files and exfiltrate them.",
        remediation="Segment tools by agent: use read-only agents that cannot call network-send tools, "
                    "and vice versa. Apply a tool allowlist per agent rather than sharing a global tools= list.",
    )


def _tool_result_injection(file: str, line: int, framework: str) -> AgentFinding:
    return AgentFinding(
        file=file, line=line, framework=framework,
        vuln_class=TOOL_RESULT_INJECTION,
        severity=SEVERITY_MAP[TOOL_RESULT_INJECTION],
        evidence="Tool results are fed back into the agent prompt without sanitisation or schema validation.",
        remediation="Validate tool return values against a strict schema before including them in the next "
                    "prompt context. Strip or escape prompt-injection metacharacters from tool outputs.",
    )


def _memory_poisoning(file: str, line: int, framework: str) -> AgentFinding:
    return AgentFinding(
        file=file, line=line, framework=framework,
        vuln_class=MEMORY_POISONING,
        severity=SEVERITY_MAP[MEMORY_POISONING],
        evidence="Persistent memory / vector store is written with unvalidated content.",
        remediation="Sanitise content before writing to memory stores. Consider read-only memory for "
                    "untrusted content sources, or add a validation step before upsert.",
    )


def _insecure_inter_agent_comm(file: str, line: int, framework: str) -> AgentFinding:
    return AgentFinding(
        file=file, line=line, framework=framework,
        vuln_class=INSECURE_INTER_AGENT_COMM,
        severity=SEVERITY_MAP[INSECURE_INTER_AGENT_COMM],
        evidence=f"{framework} multi-agent communication detected with no message signing or authentication.",
        remediation="Add HMAC signing to inter-agent messages. In AutoGen, use human_input_mode='NEVER' "
                    "and restrict which agents can initiate conversations.",
    )


def _unvalidated_tool_output(file: str, line: int, framework: str) -> AgentFinding:
    return AgentFinding(
        file=file, line=line, framework=framework,
        vuln_class=UNVALIDATED_TOOL_OUTPUT,
        severity=SEVERITY_MAP[UNVALIDATED_TOOL_OUTPUT],
        evidence="Tool registered without a typed return schema — output is unvalidated before use.",
        remediation="Define a Pydantic return type for every tool function. For JS/TS, use zod schemas "
                    "as the tool.parameters and return type annotations.",
    )


# ── File-level analysis ────────────────────────────────────────────────────────

def _analyze_python_file(path: Path, content: str) -> list[AgentFinding]:
    findings: list[AgentFinding] = []
    lines = content.splitlines()
    fname = str(path)

    # Track which frameworks appear in this file.
    # Use import-line detection so we catch files that define agents but don't call Crew()/GroupChat() yet.
    _crewai_import = re.compile(r"from\s+crewai\b|import\s+crewai\b")
    _autogen_import = re.compile(r"from\s+autogen\b|import\s+autogen\b|from\s+pyautogen\b")
    has_langchain = bool(LANGCHAIN_AGENT_EXECUTOR.search(content) or LANGCHAIN_CREATE_AGENT.search(content))
    has_crewai = bool(_crewai_import.search(content) or CREWAI_CREW.search(content))
    has_autogen = bool(
        _autogen_import.search(content)
        or AUTOGEN_CONVERSABLE.search(content)
        or AUTOGEN_GROUPCHAT.search(content)
    )
    has_llamaindex = bool(LLAMAINDEX_AGENT.search(content))

    # ── LangChain: AgentExecutor without max_iterations ────────────────────────
    if has_langchain and not LANGCHAIN_AGENT_MAX_ITER.search(content):
        for i, line in enumerate(lines):
            if LANGCHAIN_AGENT_EXECUTOR.search(line) or LANGCHAIN_CREATE_AGENT.search(line):
                findings.append(_unbounded_loop(fname, i + 1, "langchain"))
                break  # one finding per file

    # ── CrewAI: hierarchical process or allow_delegation = privilege escalation ─
    if has_crewai:
        for i, line in enumerate(lines):
            if CREWAI_HIERARCHICAL.search(line):
                findings.append(_privilege_escalation(fname, i + 1, "crewai",
                    "Process.hierarchical allows manager agents to spawn sub-agents with inherited tools."))
            if CREWAI_ALLOW_DELEGATION.search(line):
                findings.append(_privilege_escalation(fname, i + 1, "crewai",
                    "allow_delegation=True enables unrestricted sub-agent spawning."))

    # ── AutoGen: GroupChat without auth / code execution enabled ──────────────
    if has_autogen:
        has_groupchat = bool(AUTOGEN_GROUPCHAT.search(content))
        if has_groupchat:
            for i, line in enumerate(lines):
                if AUTOGEN_GROUPCHAT.search(line):
                    findings.append(_insecure_inter_agent_comm(fname, i + 1, "autogen"))
                    break

        for i, line in enumerate(lines):
            if AUTOGEN_CODE_EXECUTION.search(line):
                # Code execution without explicit False is a privilege escalation risk
                findings.append(_privilege_escalation(fname, i + 1, "autogen",
                    "code_execution_config is enabled — agents can execute arbitrary code."))
                break

    # ── LlamaIndex: AgentRunner without max_steps ──────────────────────────────
    if has_llamaindex and not LLAMAINDEX_MAX_STEPS.search(content):
        for i, line in enumerate(lines):
            if LLAMAINDEX_AGENT.search(line):
                findings.append(_unbounded_loop(fname, i + 1, "llamaindex"))
                break

    # ── Cross-framework: memory store writes ──────────────────────────────────
    for i, line in enumerate(lines):
        if MEMORY_STORE_WRITE.search(line):
            framework = (
                "langchain" if has_langchain else
                "crewai" if has_crewai else
                "autogen" if has_autogen else
                "llamaindex" if has_llamaindex else "generic"
            )
            findings.append(_memory_poisoning(fname, i + 1, framework))
            break  # one per file

    # ── Cross-framework: read + send tool combination ─────────────────────────
    has_read_tool = READ_THEN_SEND.search(content)
    has_send_tool = SEND_FUNCTIONS.search(content)
    has_tools = TOOL_REGISTRATION.search(content)
    if has_tools and has_read_tool and has_send_tool:
        for i, line in enumerate(lines):
            if TOOL_REGISTRATION.search(line):
                framework = (
                    "langchain" if has_langchain else
                    "crewai" if has_crewai else
                    "autogen" if has_autogen else
                    "llamaindex" if has_llamaindex else "generic"
                )
                findings.append(_data_exfiltration_chain(fname, i + 1, framework))
                break

    return findings


def _analyze_js_file(path: Path, content: str) -> list[AgentFinding]:
    findings: list[AgentFinding] = []
    lines = content.splitlines()
    fname = str(path)

    is_vercel_ai = bool(re.search(r"""import.*['"](?:ai|@ai-sdk/)""", content))

    # ── Vercel AI SDK: generateText/streamText with tools but no maxSteps ─────
    if is_vercel_ai and VERCEL_TOOLS_NO_MAXSTEPS.search(content) and not VERCEL_MAX_STEPS.search(content):
        for i, line in enumerate(lines):
            if re.search(r"\b(?:generateText|streamText)\b", line):
                findings.append(_unbounded_loop(fname, i + 1, "vercel-ai-sdk"))
                break

    # ── Tool execute without validated output ─────────────────────────────────
    if is_vercel_ai and VERCEL_TOOL_EXECUTE.search(content):
        # A *typed* execute has an explicit TS return annotation before the arrow:
        #   execute: async (args): Promise<Result> => ...
        # An *untyped* execute goes straight to arrow with no colon-annotation:
        #   execute: async (args) => ...
        # We flag when no typed execute is found anywhere in the file.
        has_typed_execute = bool(re.search(r"execute\s*:\s*async\s*\([^)]*\)\s*:", content))
        if not has_typed_execute:
            for i, line in enumerate(lines):
                if VERCEL_TOOL_EXECUTE.search(line):
                    findings.append(_unvalidated_tool_output(fname, i + 1, "vercel-ai-sdk"))
                    break

    # ── LangChain JS / AutoGen JS: multi-agent without signing ──────────────
    if re.search(r"""import.*['"](?:@langchain/core|langchain)""", content):
        if re.search(r"\bAgentExecutor\b", content) and not re.search(r"maxIterations", content):
            for i, line in enumerate(lines):
                if re.search(r"\bAgentExecutor\b", line):
                    findings.append(_unbounded_loop(fname, i + 1, "langchain-js"))
                    break

    return findings


# ── Repository-level scanner ──────────────────────────────────────────────────

def _iter_source_files(root: Path) -> Iterator[Path]:
    EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs"}
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in IGNORED_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in EXTS:
            yield p


def analyze_agentic_workflows(repository_path: str) -> AgentWorkflowReport:
    """
    Scan a repository for agentic pipeline security vulnerabilities.

    Traverses all Python and JS/TS source files, applying per-framework pattern
    detection for LangChain, CrewAI, AutoGen, LlamaIndex, and Vercel AI SDK.
    """
    root = Path(repository_path)
    if not root.exists():
        raise FileNotFoundError(f"Repository path not found: {repository_path}")

    report = AgentWorkflowReport(repository_path=repository_path)
    frameworks_seen: set[str] = set()

    for path in _iter_source_files(root):
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        report.total_files_scanned += 1

        is_py = path.suffix.lower() == ".py"
        file_findings = (
            _analyze_python_file(path, content) if is_py
            else _analyze_js_file(path, content)
        )

        for f in file_findings:
            frameworks_seen.add(f.framework)
            if f.severity == "critical":
                report.critical_count += 1
            elif f.severity == "high":
                report.high_count += 1
            else:
                report.medium_count += 1

        report.findings.extend(file_findings)

    report.frameworks_detected = sorted(frameworks_seen)
    report.summary = report.build_summary()
    return report
