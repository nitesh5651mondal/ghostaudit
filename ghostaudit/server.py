"""
GhostAudit Production REST API (FastAPI)
Bridges the React/Vite frontend with the local Gemma model (Argus, Cerberus, Prometheus).
Provides streaming and single-go execution, custom data input, and report downloads.
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uvicorn

from ghostaudit.core.orchestrator import GhostAuditOrchestrator
from ghostaudit.scenarios.data import SCENARIOS

app = FastAPI(
    title="GhostAudit Engine API",
    description="Backend powering the React/Vite Cyber-Forensics Mission Control",
    version="2.0.0"
)

# Enable CORS for React frontend (Vite default: http://localhost:5173, Vercel deployments, etc.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class IncidentRequest(BaseModel):
    target_name: str
    raw_logs: str
    source_code: str
    model_name: Optional[str] = "gemma2:2b"
    ollama_host: Optional[str] = "http://localhost:11434"


@app.get("/api/health")
def health_check():
    return {"status": "online", "system": "GhostAudit Cyber Engine", "version": "2.0.0"}


@app.get("/api/scenarios")
def get_scenarios():
    return {
        "scenarios": [
            {
                "id": k,
                "title": v["title"],
                "logs": v["logs"].strip(),
                "source": v["source"].strip()
            }
            for k, v in SCENARIOS.items()
        ]
    }


@app.post("/api/triage")
def run_triage(req: IncidentRequest):
    """Run all 3 models in one go (Argus -> Cerberus -> Prometheus) on custom user data."""
    if not req.raw_logs.strip() or not req.source_code.strip():
        raise HTTPException(status_code=400, detail="Both raw_logs and source_code are required.")

    orchestrator = GhostAuditOrchestrator(
        model_name=req.model_name or "gemma2:2b",
        ollama_host=req.ollama_host or "http://localhost:11434"
    )

    report = orchestrator.run_investigation(
        target_name=req.target_name,
        raw_logs=req.raw_logs,
        source_code=req.source_code
    )

    return report.model_dump()


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
