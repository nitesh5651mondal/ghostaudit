"""
Pre-bundled real-world security incident scenarios for GhostAudit
Enables instant 10-second testing and verification for hackathon judges.
"""

SCENARIOS = {
    "1_sql_injection_auth_bypass": {
        "title": "CWE-89: SQL Injection Authentication Bypass in Session Handler",
        "logs": """
2026-10-14 02:40:55.104 [INFO] [HTTP-Worker-12] Incoming POST /api/v1/auth/login from 192.168.1.105
2026-10-14 02:40:55.105 [DEBUG] [auth_service] Evaluating user credential payload: username="admin' OR '1'='1"
2026-10-14 02:40:55.120 [ERROR] [db_session_manager] DB Execution Syntax Warning near ''1'='1''
2026-10-14 02:41:09.112 [CRITICAL] [auth_service] CRITICAL: Master session returned user_id=1 (root_admin) without password validation!
2026-10-14 02:41:09.115 [DEBUG] [auth_service] Active API key logged: api_key='mock_dummy_key_sample_test_only_0000'
2026-10-14 02:41:09.430 [FATAL] [HTTP-Worker-12] Session hijacking detected! Token issued: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Traceback (most recent call last):
  File "app/main.py", line 42, in handle_request
    response = auth_service.verify_session(token, user_input)
  File "app/auth_service.py", line 84, in verify_session
    cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")
DatabaseIntegrityViolation: Uncontrolled syntax injection in query stream.
""",
        "source": """
# app/auth_service.py
import sqlite3

def verify_session(token: str, user_input: str):
    conn = sqlite3.connect("production.db")
    cursor = conn.cursor()
    
    # Vulnerable direct string interpolation without prepared statement
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    record = cursor.fetchone()
    
    if record:
        return {"status": "authenticated", "user": record[0]}
    return {"status": "denied"}
"""
    },
    "2_rce_insecure_deserialization": {
        "title": "CWE-502: Remote Code Execution via Insecure Python Pickle Deserialization",
        "logs": """
2026-10-14 04:12:01.002 [INFO] [Worker-04] Incoming cache retrieval for task_id: payload_task_99
2026-10-14 04:12:01.050 [WARNING] [cache_engine] Deserializing untrusted binary payload from client stream...
2026-10-14 04:12:01.099 [ALERT] [kernel_audit] Spawned unauthorized child subprocess /bin/sh (PID: 49201)
2026-10-14 04:12:01.100 [CRITICAL] [kernel_audit] Outbound connection attempted to 10.0.4.88:4444 (Reverse Shell Triggered)
Traceback (most recent call last):
  File "app/cache_manager.py", line 37, in load_cached_payload
    payload = pickle.loads(raw_bytes)
_pickle.UnpicklingError: Subprocess spawned during unpickling: /bin/sh
""",
        "source": """
# app/cache_manager.py
import pickle
import base64

def load_cached_payload(raw_b64_data: str):
    # Insecure deserialization of arbitrary untrusted binary input
    raw_bytes = base64.b64decode(raw_b64_data)
    payload = pickle.loads(raw_bytes)
    return payload
"""
    },
    "3_ssrf_and_credential_exposure": {
        "title": "CWE-918: Server-Side Request Forgery (SSRF) & AWS IAM Metadata Exfiltration",
        "logs": """
2026-10-14 08:33:12.891 [INFO] [WebhookRunner] Processing outgoing webhook request: target_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
2026-10-14 08:33:13.102 [WARN] [network_filter] Request dispatched to cloud metadata endpoint!
2026-10-14 08:33:13.400 [CRITICAL] [WebhookRunner] Exfiltration response received! AccessKeyId: AKIAIOSFODNN7EXAMPLE
2026-10-14 08:33:13.405 [CRITICAL] [WebhookRunner] SecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY exposed in telemetry!
""",
        "source": """
# app/webhook_service.py
import requests

def trigger_webhook(user_provided_url: str, event_data: dict):
    # Missing URL scheme, domain whitelist and IP blacklist checking
    response = requests.post(user_provided_url, json=event_data, timeout=5)
    return response.status_code
"""
    }
}
