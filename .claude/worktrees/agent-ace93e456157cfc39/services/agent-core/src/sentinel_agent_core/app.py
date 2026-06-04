import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from posthog import Posthog
from pydantic import BaseModel

from .analyzers.import_graph import analyze_attack_surface, AttackSurfaceReport
from .analyzers.llm_callchain import analyze_llm_callchains, LlmCallChainReport
from .analyzers.agentic_workflow import analyze_agentic_workflows, AgentWorkflowReport

load_dotenv()

posthog = Posthog(
    api_key=os.environ["POSTHOG_API_KEY"],
    host=os.environ.get("POSTHOG_HOST", "https://eu.i.posthog.com"),
)


class ServiceStatus(BaseModel):
    service: str
    status: str
    version: str
    capabilities: list[str]


class LlmCallChainRequest(BaseModel):
    repository_path: str


class LlmCallSiteResponse(BaseModel):
    file: str
    line: int
    framework: str
    call_expression: str
    input_classification: str
    risk_level: str
    context_snippet: str
    prompt_variables: list[str]


class LlmCallChainResponse(BaseModel):
    repository_path: str
    call_sites: list[LlmCallSiteResponse]
    total_files_scanned: int
    frameworks_detected: list[str]
    direct_injection_surface: int
    indirect_injection_surface: int
    summary: str


class AttackSurfaceRequest(BaseModel):
    repository_path: str


class AttackSurfaceResponse(BaseModel):
    repository_path: str
    unused_packages: list[str]
    test_only_packages: list[str]
    unreachable_files: list[str]
    low_connectivity_files: list[str]
    single_use_packages: list[str]
    total_files_analyzed: int
    total_packages_analyzed: int
    edge_count: int
    attack_surface_reduction_score: float
    summary: str


class AgenticFindingResponse(BaseModel):
    file: str
    line: int
    framework: str
    vuln_class: str
    severity: str
    evidence: str
    remediation: str


class AgenticWorkflowRequest(BaseModel):
    repository_path: str


class AgenticWorkflowResponse(BaseModel):
    repository_path: str
    findings: list[AgenticFindingResponse]
    total_files_scanned: int
    frameworks_detected: list[str]
    critical_count: int
    high_count: int
    medium_count: int
    summary: str


app = FastAPI(
    title="Sentinel Agent Core",
    version="0.3.0",
    description="Intelligence orchestration and static analysis services for Sentinel.",
)


@app.get("/health", response_model=ServiceStatus)
def health() -> ServiceStatus:
    return ServiceStatus(
        service="sentinel-agent-core",
        status="ok",
        version=app.version,
        capabilities=[
            "attack_surface_analysis",
            "import_graph",
            "llm_callchain_detection",
            "agentic_workflow_security",
        ],
    )


@app.post("/analyze/llm-callchains", response_model=LlmCallChainResponse)
def analyze_llm(req: LlmCallChainRequest) -> LlmCallChainResponse:
    """
    Scan a repository for LLM API call sites and classify their prompt injection risk.

    Returns every location where an LLM API is called, whether user-controlled
    data reaches the prompt, and the injection risk classification.
    """
    try:
        report: LlmCallChainReport = analyze_llm_callchains(req.repository_path)
    except FileNotFoundError as e:
        posthog.capture("sentinel-agent-core", "analysis_failed", {
            "analysis_type": "llm_callchains",
            "error": "not_found",
        })
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        posthog.capture("sentinel-agent-core", "analysis_failed", {
            "analysis_type": "llm_callchains",
            "error": str(e),
        })
        raise HTTPException(status_code=500, detail=f"Analysis error: {e}")

    posthog.capture("sentinel-agent-core", "analysis_completed", {
        "analysis_type": "llm_callchains",
        "total_files_scanned": report.total_files_scanned,
        "frameworks_detected": report.frameworks_detected,
        "direct_injection_surface": report.direct_injection_surface,
        "indirect_injection_surface": report.indirect_injection_surface,
        "call_sites_count": len(report.call_sites),
    })

    return LlmCallChainResponse(
        repository_path=report.repository_path,
        call_sites=[
            LlmCallSiteResponse(
                file=s.file, line=s.line, framework=s.framework,
                call_expression=s.call_expression, input_classification=s.input_classification,
                risk_level=s.risk_level, context_snippet=s.context_snippet,
                prompt_variables=s.prompt_variables,
            )
            for s in report.call_sites
        ],
        total_files_scanned=report.total_files_scanned,
        frameworks_detected=report.frameworks_detected,
        direct_injection_surface=report.direct_injection_surface,
        indirect_injection_surface=report.indirect_injection_surface,
        summary=report.summary,
    )


@app.post("/analyze/attack-surface", response_model=AttackSurfaceResponse)
def analyze_surface(req: AttackSurfaceRequest) -> AttackSurfaceResponse:
    """
    Analyze a repository for attack surface reduction opportunities.

    Returns unused packages, test-only packages, unreachable files,
    and an attack surface reduction score.
    """
    try:
        report: AttackSurfaceReport = analyze_attack_surface(req.repository_path)
    except FileNotFoundError as e:
        posthog.capture("sentinel-agent-core", "analysis_failed", {
            "analysis_type": "attack_surface",
            "error": "not_found",
        })
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        posthog.capture("sentinel-agent-core", "analysis_failed", {
            "analysis_type": "attack_surface",
            "error": str(e),
        })
        raise HTTPException(status_code=500, detail=f"Analysis error: {e}")

    posthog.capture("sentinel-agent-core", "analysis_completed", {
        "analysis_type": "attack_surface",
        "total_files_analyzed": report.total_files_analyzed,
        "total_packages_analyzed": report.total_packages_analyzed,
        "attack_surface_reduction_score": report.attack_surface_reduction_score(),
        "unused_packages_count": len(report.unused_packages),
        "unreachable_files_count": len(report.unreachable_files),
    })

    return AttackSurfaceResponse(
        repository_path=report.repository_path,
        unused_packages=report.unused_packages,
        test_only_packages=report.test_only_packages,
        unreachable_files=report.unreachable_files,
        low_connectivity_files=report.low_connectivity_files,
        single_use_packages=report.single_use_packages,
        total_files_analyzed=report.total_files_analyzed,
        total_packages_analyzed=report.total_packages_analyzed,
        edge_count=report.edge_count,
        attack_surface_reduction_score=report.attack_surface_reduction_score(),
        summary=report.summary,
    )


@app.post("/analyze/agentic-workflows", response_model=AgenticWorkflowResponse)
def analyze_agentic(req: AgenticWorkflowRequest) -> AgenticWorkflowResponse:
    """
    Scan a repository for agentic pipeline security vulnerabilities.

    Detects orchestration-level risks across LangChain, CrewAI, AutoGen, LlamaIndex,
    and Vercel AI SDK: unbounded tool loops, privilege escalation between agents,
    data exfiltration chains, memory poisoning, and insecure inter-agent communication.
    """
    try:
        report: AgentWorkflowReport = analyze_agentic_workflows(req.repository_path)
    except FileNotFoundError as e:
        posthog.capture("sentinel-agent-core", "analysis_failed", {
            "analysis_type": "agentic_workflows",
            "error": "not_found",
        })
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        posthog.capture("sentinel-agent-core", "analysis_failed", {
            "analysis_type": "agentic_workflows",
            "error": str(e),
        })
        raise HTTPException(status_code=500, detail=f"Analysis error: {e}")

    posthog.capture("sentinel-agent-core", "analysis_completed", {
        "analysis_type": "agentic_workflows",
        "total_files_scanned": report.total_files_scanned,
        "frameworks_detected": report.frameworks_detected,
        "critical_count": report.critical_count,
        "high_count": report.high_count,
        "medium_count": report.medium_count,
        "findings_count": len(report.findings),
    })

    return AgenticWorkflowResponse(
        repository_path=report.repository_path,
        findings=[
            AgenticFindingResponse(
                file=f.file, line=f.line, framework=f.framework,
                vuln_class=f.vuln_class, severity=f.severity,
                evidence=f.evidence, remediation=f.remediation,
            )
            for f in report.findings
        ],
        total_files_scanned=report.total_files_scanned,
        frameworks_detected=report.frameworks_detected,
        critical_count=report.critical_count,
        high_count=report.high_count,
        medium_count=report.medium_count,
        summary=report.summary,
    )
