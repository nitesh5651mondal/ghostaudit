"""
Pre-Inference Sanitizer: High-speed local regex & heuristic engine
to mask API keys, JWT tokens, private IP ranges, passwords, and private identifiers
BEFORE feeding raw data to the LLM.
"""
import re
from typing import List, Tuple
from ghostaudit.core.models import SanitizedTelemetry


PATTERNS = [
    # AWS / Generic Secret Keys
    (r"(?i)(?:api_key|apikey|secret_key|secret|password|access_token|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{16,})['\"]?", "[REDACTED_SECRET_KEY]"),
    # JWT Tokens (ey...)
    (r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+", "[REDACTED_JWT_TOKEN]"),
    # Private IPv4 addresses (10.x, 192.168.x, 172.16-31.x)
    (r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", "[REDACTED_INTERNAL_IP]"),
    # AWS Access Key IDs
    (r"\b(AKIA|ABIA|ACCA)[0-9A-Z]{16}\b", "[REDACTED_AWS_KEY]"),
    # GitHub Personal Access Tokens (ghp_..., gho_...)
    (r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b", "[REDACTED_GITHUB_TOKEN]"),
    # Bearer tokens in headers
    (r"(?i)Authorization:\s*Bearer\s+[A-Za-z0-9_\-\.~+\/=]+", "Authorization: Bearer [REDACTED_TOKEN]"),
]


class PreInferenceSanitizer:
    """Zero-trust redactor running purely locally before prompting Gemma."""

    def sanitize(self, text: str) -> SanitizedTelemetry:
        if not text:
            return SanitizedTelemetry(
                original_length=0,
                sanitized_text="",
                redacted_secrets_count=0,
                redacted_items=[]
            )

        redacted_count = 0
        detected_categories = []
        cleaned_text = text

        for pattern, replacement in PATTERNS:
            matches = list(re.finditer(pattern, cleaned_text))
            if matches:
                redacted_count += len(matches)
                detected_categories.append(replacement.strip("[]"))
                cleaned_text = re.sub(pattern, replacement, cleaned_text)

        return SanitizedTelemetry(
            original_length=len(text),
            sanitized_text=cleaned_text,
            redacted_secrets_count=redacted_count,
            redacted_items=list(set(detected_categories))
        )
