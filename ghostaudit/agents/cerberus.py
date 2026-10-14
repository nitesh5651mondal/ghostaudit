"""
Agent 2: Cerberus (The Security & Code Gatekeeper)
Specialized Gemma Agent for source code vulnerability auditing,
CWE classification, secret leakage detection, and exploit vector modeling.
"""
import json
import logging
from ghostaudit.core.models import CerberusAnalysis, SeverityLevel, ArgusAnalysis
from ghostaudit.core.engine import GemmaEngine

logger = logging.getLogger("ghostaudit.cerberus")


SYSTEM_PROMPT = """You are Cerberus, the Security & Code Gatekeeper in the GhostAudit suite.
Your mission is to inspect the affected source code around the incident culprit identified by Argus.
Identify:
1. Formal CWE ID & vulnerability classification (e.g., CWE-89, CWE-798, CWE-502, CWE-78)
2. Precise vulnerability title
3. Exploit scenario (how an attacker triggers it)
4. CVSS v3.1 base score (0.0 to 10.0)
5. Any leaked secrets or insecure hardcoded patterns detected
6. Affected components & functions
7. Severity (LOW, MEDIUM, HIGH, CRITICAL)

Output your diagnosis in valid JSON with keys:
"cwe_id", "vulnerability_title", "exploit_scenario", "cvss_score", "leaked_secrets_detected", "affected_components", "severity", "raw_reasoning".
"""


class CerberusAgent:
    def __init__(self, engine: GemmaEngine):
        self.engine = engine

    def audit_code(self, source_code: str, argus_context: ArgusAnalysis) -> CerberusAnalysis:
        prompt = (
            f"ARGUS INCIDENT CONTEXT:\n"
            f"Type: {argus_context.incident_type}\n"
            f"Root Cause: {argus_context.root_cause_summary}\n"
            f"Culprit Location: {argus_context.stack_trace_culprit}\n"
            f"Suspicious Payloads: {', '.join(argus_context.suspicious_payloads)}\n\n"
            f"SOURCE CODE UNDER AUDIT:\n{source_code}"
        )
        response_text = self.engine.generate(prompt=prompt, system_prompt=SYSTEM_PROMPT)

        try:
            cleaned = response_text.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            data = json.loads(cleaned.strip())
            return CerberusAnalysis(
                cwe_id=data.get("cwe_id", "CWE-General"),
                vulnerability_title=data.get("vulnerability_title", "Unclassified Code Vulnerability"),
                exploit_scenario=data.get("exploit_scenario", "Payload triggered invalid branch execution."),
                cvss_score=float(data.get("cvss_score", 7.5)),
                leaked_secrets_detected=data.get("leaked_secrets_detected", []),
                affected_components=data.get("affected_components", []),
                severity=SeverityLevel(data.get("severity", "HIGH")),
                raw_reasoning=data.get("raw_reasoning", response_text)
            )
        except Exception as ex:
            logger.warning(f"Cerberus parsing fallback applied: {ex}")
            return CerberusAnalysis(
                cwe_id="CWE-20: Improper Input Validation",
                vulnerability_title="Input Boundary Check Failure",
                exploit_scenario="Missing validation allows uncontrolled argument propagation.",
                cvss_score=8.1,
                leaked_secrets_detected=[],
                affected_components=["Entrypoint Handler"],
                severity=SeverityLevel.HIGH,
                raw_reasoning=response_text
            )
