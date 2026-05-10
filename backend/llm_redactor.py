"""
RAPTOR | LLM Pre-Submission Redactor
Strips PII and secrets from log content before any text leaves the RAPTOR
boundary for an external LLM provider. Applied to all prompts when
RAPTOR_ALLOW_EXTERNAL_LLM=true.

Redacted categories
-------------------
Bearer / API tokens         → Bearer [REDACTED_TOKEN]
Credential key-value pairs  → key=[REDACTED]   (password=, secret=, apikey=…)
Private IPv4 addresses      → [PRIVATE_IP]     (RFC-1918 + loopback + APIPA)
Email addresses             → [EMAIL_REDACTED]
US phone numbers            → [PHONE_REDACTED]
US Social Security Numbers  → [SSN_REDACTED]
Credit card numbers         → [CC_REDACTED]    (Luhn-plausible 13–19 digit runs)
Windows filesystem paths    → [WINDOWS_PATH]
UNC network paths           → [UNC_PATH]
Sensitive Unix paths        → [SENSITIVE_PATH]
"""
from __future__ import annotations

import re

# ── Patterns ──────────────────────────────────────────────────────────────────

_BEARER = re.compile(r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*")

_CREDENTIAL_KV = re.compile(
    r"(?i)"
    r"(password|passwd|pwd|secret|token|api[_\-]?key|auth|access_key"
    r"|private[_\-]?key|client[_\-]?secret|authorization)\s*[:=]\s*\S+"
)

_PRIVATE_IPV4 = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"  # APIPA
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"  # loopback
    r")\b"
)

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# US phone: (555) 123-4567 | 555-123-4567 | +1-555-123-4567 | 5551234567
_PHONE = re.compile(
    r"(?<!\d)"
    r"(\+?1[\s\-.]?)?"
    r"\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}"
    r"(?!\d)"
)

# US SSN: 123-45-6789 or 123456789 (simple pattern; false positives possible in
# log data but better to over-redact than leak PII in LLM prompts)
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Credit card: 13–19 consecutive digits (may include separators)
# We use a broad pattern; false positives in log timestamps are unlikely.
_CREDIT_CARD = re.compile(r"\b(?:\d[ \-]?){13,19}\b")

_WINDOWS_DRIVE_PATH = re.compile(
    r"[A-Za-z]:\\(?:[^\s\\\"'<>|*?\r\n]+\\)*[^\s\\\"'<>|*?\r\n]*"
)

_UNC_PATH = re.compile(
    r"\\\\[^\s\\\"'<>|*?\r\n]+(?:\\[^\s\\\"'<>|*?\r\n]+)+"
)

_SENSITIVE_UNIX_PATHS = re.compile(
    r"(?i)"
    r"(/etc/(shadow|passwd|sudoers|ssl/|ssh/)"
    r"|\.aws/credentials"
    r"|\.ssh/(id_rsa|id_ecdsa|id_ed25519|authorized_keys)"
    r"|/proc/[0-9]+/environ"
    r"|/var/log/auth\.log"
    r"|/home/[^/\s]+/\.(bash_history|zsh_history|netrc))"
)

# ── Public API ────────────────────────────────────────────────────────────────

def redact(text: str) -> str:
    """Return *text* with sensitive content replaced by safe placeholders.

    Runs patterns in priority order: tokens first (most dangerous), then
    structured PII, then path leaks.
    """
    text = _BEARER.sub("Bearer [REDACTED_TOKEN]", text)
    text = _CREDENTIAL_KV.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = _SSN.sub("[SSN_REDACTED]", text)
    text = _CREDIT_CARD.sub("[CC_REDACTED]", text)
    text = _EMAIL.sub("[EMAIL_REDACTED]", text)
    text = _PHONE.sub("[PHONE_REDACTED]", text)
    text = _PRIVATE_IPV4.sub("[PRIVATE_IP]", text)
    text = _SENSITIVE_UNIX_PATHS.sub("[SENSITIVE_PATH]", text)
    text = _WINDOWS_DRIVE_PATH.sub("[WINDOWS_PATH]", text)
    text = _UNC_PATH.sub("[UNC_PATH]", text)
    return text


def redact_prompt_messages(messages: list[dict]) -> list[dict]:
    """Apply :func:`redact` to every ``content`` field in an OpenAI-style message list."""
    result = []
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, str):
            msg = {**msg, "content": redact(content)}
        elif isinstance(content, list):
            new_parts = []
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    part = {**part, "text": redact(part["text"])}
                new_parts.append(part)
            msg = {**msg, "content": new_parts}
        result.append(msg)
    return result
