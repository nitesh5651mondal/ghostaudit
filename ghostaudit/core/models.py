"""
Data models and schemas for GhostAudit multi-agent forensics pipeline.
"""
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from enum import Enum


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SanitizedTelemetry(BaseModel):
    original_length: int
    sanitized_text: str
    redacted_secrets_count: int
    redacted_items: List[str] = Field(default_factory=list)


class ArgusAnalysis(BaseModel):
    """Output from Agent 1: Argus (Log & Crash Anomaly Detective)."""
    incident_type: str = Field(description="Categorization, e.g. Unhandled Exception, Memory Corrupt, Auth Bypass, Leak")
    root_cause_summary: str = Field(description="Clear explanation of the failure signature")
    anomaly_timestamps: List[str] = Field(default_factory=list)
    stack_trace_culprit: Optional[str] = Field(None, description="Culprit file and line number")
    suspicious_payloads: List[str] = Field(default_factory=list)
    severity: SeverityLevel = SeverityLevel.HIGH
    raw_reasoning: str = ""


class CerberusAnalysis(BaseModel):
    """Output from Agent 2: Cerberus (Security & Code Vulnerability Auditor)."""
    cwe_id: str = Field(description="e.g. CWE-89 (SQLi), CWE-798 (Hardcoded Creds), CWE-502 (Insecure Deserialization)")
    vulnerability_title: str = Field(description="Concise vulnerability title")
    exploit_scenario: str = Field(description="How an attacker can trigger this flaw")
    cvss_score: float = Field(default=7.5, ge=0.0, le=10.0)
    leaked_secrets_detected: List[str] = Field(default_factory=list)
    affected_components: List[str] = Field(default_factory=list)
    severity: SeverityLevel = SeverityLevel.HIGH
    raw_reasoning: str = ""


class PrometheusAnalysis(BaseModel):
    """Output from Agent 3: Prometheus (Patch Synthesizer & Healer)."""
    git_patch_diff: str = Field(description="Unified git diff patch format")
    remediation_steps: List[str] = Field(default_factory=list)
    defense_in_depth_recommendations: List[str] = Field(default_factory=list)
    patch_verified_safe: bool = True
    raw_reasoning: str = ""


class ForensicReport(BaseModel):
    """Complete consolidated Incident Forensics Report."""
    incident_id: str
    target_name: str
    timestamp: str
    gemma_model_used: str
    sanitization_meta: SanitizedTelemetry
    argus: ArgusAnalysis
    cerberus: CerberusAnalysis
    prometheus: PrometheusAnalysis
    executive_summary: str
    status: str = "COMPLETED"
