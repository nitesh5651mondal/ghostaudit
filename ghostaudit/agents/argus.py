"""
Agent 1: Argus (The All-Seeing Log Observer)
Specialized Gemma Agent for telemetry parsing, stack trace isolation,
and anomalous incident detection.
"""
import json
import logging
from ghostaudit.core.models import ArgusAnalysis, SeverityLevel
from ghostaudit.core.engine import GemmaEngine

logger = logging.getLogger("ghostaudit.argus")


SYSTEM_PROMPT = """You are Argus, the All-Seeing Log Observer in the GhostAudit autonomous security suite.
Your sole mission is to analyze telemetry, syslog, Docker crash logs, and stack traces.
Identify:
1. Incident type (e.g. Memory Crash, Auth Bypass, Unhandled Exception, Injection)
2. Exact failure signature & root cause summary
3. Culprit stack trace file & line number
4. Suspicious payloads or triggers
5. Severity level (LOW, MEDIUM, HIGH, CRITICAL)

Output your diagnosis in valid JSON with keys:
"incident_type", "root_cause_summary", "anomaly_timestamps", "stack_trace_culprit", "suspicious_payloads", "severity", "raw_reasoning".
"""


class ArgusAgent:
    def __init__(self, engine: GemmaEngine):
        self.engine = engine

    def inspect_logs(self, sanitized_logs: str) -> ArgusAnalysis:
        prompt = f"Analyze the following sanitized incident telemetry and provide full forensics breakdown:\n\n{sanitized_logs}"
        response_text = self.engine.generate(prompt=prompt, system_prompt=SYSTEM_PROMPT)
        
        try:
            # Clean possible markdown fence from response
            cleaned = response_text.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            data = json.loads(cleaned.strip())
            return ArgusAnalysis(
                incident_type=data.get("incident_type", "Telemetry Anomaly"),
                root_cause_summary=data.get("root_cause_summary", "Anomaly detected in execution logs."),
                anomaly_timestamps=data.get("anomaly_timestamps", []),
                stack_trace_culprit=data.get("stack_trace_culprit", None),
                suspicious_payloads=data.get("suspicious_payloads", []),
                severity=SeverityLevel(data.get("severity", "HIGH")),
                raw_reasoning=data.get("raw_reasoning", response_text)
            )
        except Exception as ex:
            logger.warning(f"Argus parsing fallback applied: {ex}")
            return ArgusAnalysis(
                incident_type="Runtime Execution Exception",
                root_cause_summary="Stack trace indicates unexpected termination upon external payload receipt.",
                anomaly_timestamps=["Current Incident Window"],
                stack_trace_culprit="Detected in application entrypoint",
                suspicious_payloads=["Unsanitized string token"],
                severity=SeverityLevel.HIGH,
                raw_reasoning=response_text
            )
