"""
LLM Call Chain Detector — spec §3.4.2

"On every push, Sentinel's static analysis agent scans the codebase and:
 1. Identifies every location where an LLM API is called
 2. Maps the full data flow: what user input reaches the prompt?
 3. Builds a call chain graph per LLM invocation"

This module performs that static analysis using Python AST + regex for JS/TS.

LLM frameworks detected:
  Python:  openai, anthropic, langchain, langchain_community, langchain_openai,
           llamaindex, llama_index, google.generativeai, cohere, mistralai,
           groq, together, replicate, huggingface_hub
  JS/TS:   openai, @anthropic-ai/sdk, @langchain/core, langchain, @ai-sdk/*,
           ai (Vercel AI SDK), llamaindex, google-generativeai

For each detected call, we classify:
  - DIRECT_USER_INPUT: user-controlled data flows directly to the prompt
  - INDIRECT_INPUT: external content (DB, URL, file) flows to the prompt
  - STATIC: prompt is fully static — no external input
  - UNKNOWN: could not determine data flow

This classification drives the Prompt Injection Shield findings.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

# ── LLM API signatures ─────────────────────────────────────────────────────────

# Python: (module_pattern, call_patterns, framework_label)
PYTHON_LLM_SIGNATURES = [
    # OpenAI
    ("openai", {"ChatCompletion.create", "chat.completions.create", "Completion.create", "completions.create"}, "openai"),
    ("openai", {"Embedding.create", "embeddings.create"}, "openai-embeddings"),
    # Anthropic
    ("anthropic", {"messages.create", "Anthropic().messages", "client.messages.create"}, "anthropic"),
    # LangChain
    ("langchain", {"LLMChain", "ChatOpenAI", "ChatAnthropic", "ChatGoogleGenerativeAI", "invoke", "run", "predict"}, "langchain"),
    ("langchain_community", {"ChatOpenAI", "ChatAnthropic", "invoke"}, "langchain"),
    ("langchain_openai", {"ChatOpenAI", "OpenAI", "invoke"}, "langchain-openai"),
    # LlamaIndex
    ("llama_index", {"complete", "chat", "stream_complete", "query", "QueryEngine"}, "llamaindex"),
    ("llamaindex", {"complete", "chat", "query"}, "llamaindex"),
    # Google
    ("google.generativeai", {"generate_content", "GenerativeModel"}, "google-genai"),
    ("vertexai", {"TextGenerationModel", "ChatModel", "predict"}, "vertexai"),
    # Other providers
    ("cohere", {"generate", "chat", "Client"}, "cohere"),
    ("groq", {"chat.completions.create", "ChatCompletion"}, "groq"),
    ("mistralai", {"chat", "completion", "MistralClient"}, "mistral"),
    ("replicate", {"run", "Replicate"}, "replicate"),
    ("together", {"chat.completions.create"}, "together"),
]

JS_LLM_PATTERNS = [
    # Match: require('openai'), import openai from 'openai', etc.
    (re.compile(r"""(?:import|require)\s*\(?['"]openai['"]"""), "openai"),
    (re.compile(r"""(?:import|require)\s*\(?['"]@anthropic-ai/sdk['"]"""), "anthropic"),
    (re.compile(r"""(?:import|require)\s*\(?['"](?:langchain|@langchain/core|@langchain/openai)['"]"""), "langchain"),
    (re.compile(r"""(?:import|require)\s*\(?['"](?:ai|@ai-sdk/[^'"]+)['"]"""), "vercel-ai-sdk"),
    (re.compile(r"""(?:import|require)\s*\(?['"]llamaindex['"]"""), "llamaindex"),
    (re.compile(r"""(?:import|require)\s*\(?['"]@google/generative-ai['"]"""), "google-genai"),
    (re.compile(r"""(?:import|require)\s*\(?['"]cohere-ai['"]"""), "cohere"),
    (re.compile(r"""useChat|useCompletion|useObject|streamText|generateText|generateObject""", re.I), "vercel-ai-sdk"),
    (re.compile(r"""ChatCompletion\.create|chat\.completions\.create|client\.chat""", re.I), "openai"),
    (re.compile(r"""client\.messages\.create|anthropic\.messages""", re.I), "anthropic"),
]

# Input source classification patterns
USER_INPUT_PATTERNS = [
    # HTTP request body / query / params
    re.compile(r"""req\.(body|query|params|headers)\b"""),
    re.compile(r"""request\.(body|query|params|headers|json)\b"""),
    re.compile(r"""ctx\.(body|query|params|request)\b"""),
    re.compile(r"""event\.(body|queryStringParameters|pathParameters)\b"""),
    # Explicit user input variable names (not dict keys)
    re.compile(r"""\buser_message\b|\buser_input\b|\buser_query\b|\buser_content\b""", re.I),
    re.compile(r"""\binput\s*=|\binput\s*\[|\binput\.get\b""", re.I),
    # Form/URL input
    re.compile(r"""form\.get\s*\(|FormData\b|URLSearchParams\b|getFormData\b"""),
    # Explicit helper names
    re.compile(r"""\bgetInput\b|\bgetUserInput\b|\bgetUserMessage\b""", re.I),
    # await req.json() / await request.json() — common in fetch handlers
    re.compile(r"""await\s+req(?:uest)?\.(json|text|formData)\s*\(\)""", re.I),
]

INDIRECT_INPUT_PATTERNS = [
    re.compile(r"""fetch\s*\(|axios\.|requests\.|httpx\.|urllib"""),
    re.compile(r"""open\s*\(|read_text|read_file|load_file""", re.I),
    re.compile(r"""cursor\.|db\.|mongo\.|supabase\.|prisma\.""", re.I),
    re.compile(r"""email|gmail|outlook|smtp""", re.I),
    re.compile(r"""document|pdf|txt|csv|xlsx""", re.I),
]


@dataclass
class LlmCallSite:
    """A detected LLM API call site."""
    file: str
    line: int
    framework: str
    call_expression: str  # truncated source of the call
    input_classification: str  # DIRECT_USER_INPUT | INDIRECT_INPUT | STATIC | UNKNOWN
    risk_level: str  # critical | high | medium | low
    context_snippet: str  # surrounding code (±3 lines)
    prompt_variables: list[str] = field(default_factory=list)  # variable names feeding the prompt


@dataclass
class LlmCallChainReport:
    repository_path: str
    call_sites: list[LlmCallSite] = field(default_factory=list)
    total_files_scanned: int = 0
    frameworks_detected: list[str] = field(default_factory=list)
    direct_injection_surface: int = 0    # sites with DIRECT_USER_INPUT
    indirect_injection_surface: int = 0  # sites with INDIRECT_INPUT
    summary: str = ""

    def risk_summary(self) -> str:
        if not self.call_sites:
            return "No LLM API calls detected in codebase."
        parts = []
        if self.direct_injection_surface:
            parts.append(f"{self.direct_injection_surface} direct user-input injection surface(s)")
        if self.indirect_injection_surface:
            parts.append(f"{self.indirect_injection_surface} indirect injection surface(s) (DB/URL/file)")
        static = len(self.call_sites) - self.direct_injection_surface - self.indirect_injection_surface
        if static:
            parts.append(f"{static} static/safe call(s)")
        frameworks = ", ".join(sorted(set(self.frameworks_detected)))
        return (
            f"Detected {len(self.call_sites)} LLM call site(s) using: {frameworks}. "
            + (", ".join(parts) if parts else "All appear static.")
        )


IGNORED_DIRS = {
    ".git", "node_modules", ".turbo", ".next", "dist", "build", "target",
    "__pycache__", ".venv", "venv", ".pytest_cache", "coverage",
}


def _iter_source_files(root: Path) -> Iterator[Path]:
    EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs"}
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in EXTS:
            yield path


def _classify_input(code_context: str) -> str:
    for pattern in USER_INPUT_PATTERNS:
        if pattern.search(code_context):
            return "DIRECT_USER_INPUT"
    for pattern in INDIRECT_INPUT_PATTERNS:
        if pattern.search(code_context):
            return "INDIRECT_INPUT"
    # If the call contains template literals or f-strings with variables, it's unknown
    if re.search(r'\{[^}]+\}|f".*\{|f\'.*\{', code_context):
        return "UNKNOWN"
    return "STATIC"


def _risk_from_classification(classification: str) -> str:
    return {
        "DIRECT_USER_INPUT": "critical",
        "INDIRECT_INPUT": "high",
        "UNKNOWN": "medium",
        "STATIC": "low",
    }.get(classification, "medium")


def _context_snippet(lines: list[str], line_no: int, ctx_lines: int = 3) -> str:
    start = max(0, line_no - ctx_lines - 1)
    end = min(len(lines), line_no + ctx_lines)
    return "\n".join(lines[start:end])


# ── Python AST analysis ───────────────────────────────────────────────────────

def _analyze_python_file(path: Path, root: Path) -> list[LlmCallSite]:
    rel = str(path.relative_to(root))
    sites: list[LlmCallSite] = []

    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError):
        return sites

    lines = source.splitlines()

    # Detect which LLM modules are imported
    imported_modules: set[str] = set()
    framework_by_alias: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name.split(".")[0])
                asname = alias.asname or alias.name
                for mod_pattern, _, framework in PYTHON_LLM_SIGNATURES:
                    if alias.name.startswith(mod_pattern):
                        framework_by_alias[asname.split(".")[0]] = framework
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_modules.add(node.module.split(".")[0])
                for mod_pattern, _, framework in PYTHON_LLM_SIGNATURES:
                    if node.module.startswith(mod_pattern):
                        for alias in node.names:
                            framework_by_alias[alias.asname or alias.name] = framework

    if not framework_by_alias and not imported_modules:
        return sites

    # Find call sites
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_str = ast.unparse(node).strip()
        framework = None

        # Check if this call looks like an LLM call
        for alias, fw in framework_by_alias.items():
            if alias in call_str:
                framework = fw
                break

        if not framework:
            for mod_pattern, call_set, fw in PYTHON_LLM_SIGNATURES:
                base = mod_pattern.split(".")[0]
                if base in imported_modules:
                    for call_sig in call_set:
                        if call_sig.split(".")[-1] in call_str:
                            framework = fw
                            break
                if framework:
                    break

        if not framework:
            continue

        # Filter out client constructors (OpenAI(), Anthropic(), etc.)
        # We want actual invocation calls, not instantiation
        INVOCATION_KEYWORDS = {
            "create", "invoke", "run", "predict", "generate", "chat", "complete",
            "stream", "embed", "query", "search", "call", "forward",
        }
        # Check if any invocation keyword is in the call string (beyond just the class name)
        call_method = ""
        if isinstance(node.func, ast.Attribute):
            call_method = node.func.attr
        elif isinstance(node.func, ast.Name):
            call_method = node.func.id

        if call_method.lower() not in INVOCATION_KEYWORDS and not any(
            kw in call_method.lower() for kw in INVOCATION_KEYWORDS
        ):
            # This is likely just a constructor — skip
            continue

        line_no = node.lineno
        # Use a wider context (±10 lines) for better indirect-input detection
        snippet = _context_snippet(lines, line_no, ctx_lines=10)
        classification = _classify_input(snippet)
        risk = _risk_from_classification(classification)

        # Extract variable names from keyword args (messages=, prompt=, content=)
        prompt_vars: list[str] = []
        for kw in node.keywords:
            if kw.arg in ("messages", "prompt", "content", "text", "user", "system"):
                if isinstance(kw.value, ast.Name):
                    prompt_vars.append(kw.value.id)
                elif isinstance(kw.value, (ast.List, ast.Tuple)):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Name):
                            prompt_vars.append(elt.id)

        sites.append(LlmCallSite(
            file=rel,
            line=line_no,
            framework=framework,
            call_expression=call_str[:200],
            input_classification=classification,
            risk_level=risk,
            context_snippet=snippet,
            prompt_variables=prompt_vars,
        ))

    return sites


# ── JavaScript / TypeScript analysis ─────────────────────────────────────────

def _analyze_js_file(path: Path, root: Path) -> list[LlmCallSite]:
    rel = str(path.relative_to(root))
    sites: list[LlmCallSite] = []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return sites

    # Find which LLM frameworks are imported
    detected_frameworks: set[str] = set()
    for pattern, framework in JS_LLM_PATTERNS:
        if pattern.search(content):
            detected_frameworks.add(framework)

    if not detected_frameworks:
        return sites

    lines = content.splitlines()

    # Find actual API call lines — look for .create(, .chat(, streamText(, etc.
    call_patterns = [
        re.compile(r"""(?:completions?\.create|messages\.create|generateText|streamText|generateObject|useChat|chat\.complete)\s*\(""", re.I),
        re.compile(r"""new\s+(?:ChatOpenAI|ChatAnthropic|OpenAI|Anthropic|LlamaIndex|CohereClient)\s*\(""", re.I),
        re.compile(r"""model\.invoke\s*\(|chain\.run\s*\(|chain\.invoke\s*\(""", re.I),
    ]

    for i, line in enumerate(lines):
        for pattern in call_patterns:
            if pattern.search(line):
                snippet = _context_snippet(lines, i + 1)
                classification = _classify_input(snippet)
                risk = _risk_from_classification(classification)

                # Guess framework from context
                framework = "unknown"
                for _, fw in JS_LLM_PATTERNS:
                    if fw in detected_frameworks:
                        framework = fw
                        break

                sites.append(LlmCallSite(
                    file=rel,
                    line=i + 1,
                    framework=framework,
                    call_expression=line.strip()[:200],
                    input_classification=classification,
                    risk_level=risk,
                    context_snippet=snippet,
                ))
                break  # one site per line

    return sites


# ── Main entry point ──────────────────────────────────────────────────────────

def analyze_llm_callchains(root_path: str | Path) -> LlmCallChainReport:
    """
    Scan a repository for LLM API call sites and classify their injection risk.
    Returns an LlmCallChainReport with all detected sites and risk classification.
    """
    root = Path(root_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Repository path does not exist: {root}")

    report = LlmCallChainReport(repository_path=str(root))
    frameworks: set[str] = set()

    for file_path in _iter_source_files(root):
        report.total_files_scanned += 1

        if file_path.suffix == ".py":
            sites = _analyze_python_file(file_path, root)
        else:
            sites = _analyze_js_file(file_path, root)

        for site in sites:
            frameworks.add(site.framework)
            if site.input_classification == "DIRECT_USER_INPUT":
                report.direct_injection_surface += 1
            elif site.input_classification == "INDIRECT_INPUT":
                report.indirect_injection_surface += 1

        report.call_sites.extend(sites)

    report.frameworks_detected = sorted(frameworks)
    report.summary = report.risk_summary()
    return report
