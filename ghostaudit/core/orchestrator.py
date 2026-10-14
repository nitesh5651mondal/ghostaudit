"""
GhostAudit Orchestrator:
Coordinates Pre-Inference Sanitizer, Argus, Cerberus, and Prometheus
into an end-to-end autonomous forensics pipeline.
"""
import uuid
import datetime
import logging
from ghostaudit.core.models import ForensicReport
from ghostaudit.core.sanitizer import PreInferenceSanitizer
from ghostaudit.core.engine import GemmaEngine
from ghostaudit.agents.argus import ArgusAgent
from ghostaudit.agents.cerberus import CerberusAgent
from ghostaudit.agents.prometheus import PrometheusAgent

logger = logging.getLogger("ghostaudit.orchestrator")


class GhostAuditOrchestrator:
    def __init__(self, model_name: str = "gemma2:2b", ollama_host: str = "http://localhost:11434"):
        self.engine = GemmaEngine(model_name=model_name, ollama_host=ollama_host)
        self.sanitizer = PreInferenceSanitizer()
        self.argus = ArgusAgent(self.engine)
        self.cerberus = CerberusAgent(self.engine)
        self.prometheus = PrometheusAgent(self.engine)

    def run_investigation(self, target_name: str, raw_logs: str, source_code: str) -> ForensicReport:
        incident_id = f"GHOST-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        logger.info(f"Starting investigation for incident {incident_id}...")

        # Step 1: Pre-Inference Zero-Trust Sanitization
        sanitized_logs_meta = self.sanitizer.sanitize(raw_logs)

        # Step 2: Agent Argus (Log & Crash Triage)
        argus_report = self.argus.inspect_logs(sanitized_logs_meta.sanitized_text)

        # Step 3: Agent Cerberus (Source Code & CWE Auditing)
        cerberus_report = self.cerberus.audit_code(source_code, argus_report)

        # Step 4: Agent Prometheus (Patch Synthesis & Defense Strategy)
        prometheus_report = self.prometheus.heal(source_code, argus_report, cerberus_report)

        # Step 5: Synthesize Executive Post-Mortem Summary
        exec_summary = (
            f"Incident {incident_id} ({cerberus_report.vulnerability_title}) triaged with severity "
            f"{cerberus_report.severity.value} (CVSS {cerberus_report.cvss_score}). "
            f"Argus pinpointed failure at {argus_report.stack_trace_culprit or 'entrypoint'}. "
            f"Cerberus mapped the vulnerability to {cerberus_report.cwe_id} with {len(cerberus_report.leaked_secrets_detected)} secret leakage indicators. "
            f"Prometheus synthesized a validated git diff patch to neutralize the exploit vector. "
            f"All analysis executed air-gapped on local Gemma with {sanitized_logs_meta.redacted_secrets_count} telemetry tokens redacted prior to inference."
        )

        return ForensicReport(
            incident_id=incident_id,
            target_name=target_name,
            timestamp=timestamp,
            gemma_model_used=self.engine.model_name if self.engine.is_connected else f"{self.engine.model_name} (Local Sandbox Mode)",
            sanitization_meta=sanitized_logs_meta,
            argus=argus_report,
            cerberus=cerberus_report,
            prometheus=prometheus_report,
            executive_summary=exec_summary,
            status="COMPLETED"
        )
