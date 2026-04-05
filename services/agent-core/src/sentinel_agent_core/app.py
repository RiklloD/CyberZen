from fastapi import FastAPI
from pydantic import BaseModel


class ServiceStatus(BaseModel):
    service: str
    status: str
    responsibility: str


app = FastAPI(
    title="Sentinel Agent Core",
    version="0.1.0",
    description="Early orchestration scaffold for planner/executor style services.",
)


@app.get("/health", response_model=ServiceStatus)
def health() -> ServiceStatus:
    return ServiceStatus(
        service="sentinel-agent-core",
        status="ok",
        responsibility="workflow planning and intelligence orchestration scaffold",
    )
