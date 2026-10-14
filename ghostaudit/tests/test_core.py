"""
Unit tests for GhostAudit core components:
- Pre-inference secret sanitizer
- Gemma fallback engine
- Argus, Cerberus, and Prometheus agents
- End-to-end orchestration
"""
import pytest
from ghostaudit.core.sanitizer import PreInferenceSanitizer
from ghostaudit.core.engine import GemmaEngine
from ghostaudit.core.orchestrator import GhostAuditOrchestrator
from ghostaudit.scenarios.data import SCENARIOS


def test_sanitizer_redacts_credentials_and_ips():
    sanitizer = PreInferenceSanitizer()
    raw = "User admin logged in from 192.168.1.50 with api_key='sk_live_secret123456789' and AKIAIOSFODNN7EXAMPLE"
    result = sanitizer.sanitize(raw)
    
    assert result.redacted_secrets_count >= 2
    assert "192.168.1.50" not in result.sanitized_text
    assert "sk_live_secret123456789" not in result.sanitized_text
    assert "AKIAIOSFODNN7EXAMPLE" not in result.sanitized_text
    assert "[REDACTED_INTERNAL_IP]" in result.sanitized_text


def test_gemma_engine_fallback():
    engine = GemmaEngine()
    response = engine.generate("test prompt", system_prompt="argus log analysis")
    assert response is not None
    assert len(response) > 0


def test_orchestrator_pipeline():
    scenario = SCENARIOS["1_sql_injection_auth_bypass"]
    orchestrator = GhostAuditOrchestrator()
    report = orchestrator.run_investigation(
        target_name=scenario["title"],
        raw_logs=scenario["logs"],
        source_code=scenario["source"]
    )
    
    assert report.incident_id.startswith("GHOST-")
    assert report.status == "COMPLETED"
    assert report.argus is not None
    assert report.cerberus is not None
    assert report.prometheus is not None
    assert report.prometheus.git_patch_diff is not None
    assert "--- a/" in report.prometheus.git_patch_diff
