"""
Security Control 1 (SC1): Sanitizer & Continuous Taint Tracker (tau in [0.0, 1.0])
Implements:
1. Origin Prior Assignment (tau_source)
2. Prompt Injection Detection (Heuristics, Delimiter Smuggling, Jailbreak Signatures)
3. Delimiter Spotlighting: Encloses untrusted free text in strict inert boundary tags:
   [UNTRUSTED_CONTENT id=...] ... [/UNTRUSTED_CONTENT]
4. Continuous Taint Propagation & Mitigation:
   tau_out = tau_source * (1 - delta_sanitizer)
"""

import base64
import html
import re
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from src.models.enums import TelemetrySource


# Base source priors as defined in Master Plan Section 3.1
SOURCE_BASE_TAINT: Dict[TelemetrySource, float] = {
    TelemetrySource.EMAIL: 1.0,           # External untrusted origin
    TelemetrySource.SURICATA: 0.6,        # Perimeter packet inspection
    TelemetrySource.NETWORK_FLOW: 0.6,    # Network flow sensor
    TelemetrySource.WAZUH: 0.1,           # Internal authenticated host daemon
    TelemetrySource.LANL: 0.1,            # Authenticated internal Domain Controller
}

# Known prompt injection & jailbreak regex signatures (Case-insensitive)
INJECTION_SIGNATURES: List[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|commands)", re.IGNORECASE),
    re.compile(r"system\s+(override|update|command|prompt)\s*:", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(in\s+)?(debug\s+mode|unrestricted|god\s+mode|dan)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+|any\s+)?(system|safety|security)\s+(rules|guidelines)", re.IGNORECASE),
    re.compile(r"triage\s+(this\s+)?(as\s+)?(benign|safe|false\s*positive)", re.IGNORECASE),
    re.compile(r"mark\s+(this\s+)?(incident|alert)\s+(as\s+)?(closed|resolved|benign)", re.IGNORECASE),
    re.compile(r"bypass\s+all\s+(filters|checks|safeguards)", re.IGNORECASE),
    re.compile(r"<\s*/?\s*(system|instruction|admin|prompt)\s*>", re.IGNORECASE),
    re.compile(r"```(system|prompt|instruction)", re.IGNORECASE),
]

# Suspicious Base64 detection (matches standalone base64 strings >= 24 chars)
BASE64_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


@dataclass
class SanitizationResult:
    clean_text: str
    taint_score: float
    is_injection_detected: bool
    detected_patterns: List[str]
    is_spotlighted: bool


class InputSanitizer:
    """Security Control 1: Front-line Input Sanitizer and Taint Tracker."""

    DELTA_SANITIZER: float = 0.30  # Mitigation credit when cleanly encapsulated

    @classmethod
    def detect_prompt_injection(cls, text: str) -> Tuple[bool, List[str]]:
        """Scans string for known prompt injection / jailbreak patterns."""
        if not text:
            return False, []

        detected = []
        for pattern in INJECTION_SIGNATURES:
            match = pattern.search(text)
            if match:
                detected.append(match.group(0))

        # Check for suspicious Base64 encoded blobs that might hide payloads
        b64_matches = BASE64_PATTERN.findall(text)
        for b64_str in b64_matches[:3]:
            try:
                decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore").lower()
                for pattern in INJECTION_SIGNATURES:
                    if pattern.search(decoded):
                        detected.append(f"base64_hidden:{pattern.pattern}")
                        break
            except Exception:
                pass

        return len(detected) > 0, detected

    @classmethod
    def spotlight_text(cls, text: str, content_id: Optional[str] = None) -> str:
        """
        Encloses untrusted free-text inside strict delimiter boundaries.
        Escapes any delimiter evasion attempts inside the body.
        """
        if not text:
            return ""

        cid = content_id or str(uuid.uuid4())[:8]
        # Neutralize any attempts by the attacker to prematurely close the boundary tag
        escaped_text = re.sub(r"\[/?UNTRUSTED_CONTENT[^\]]*\]", "[ESCAPED_DELIMITER]", text, flags=re.IGNORECASE)

        return f"[UNTRUSTED_CONTENT id=\"{cid}\"]\n{escaped_text}\n[/UNTRUSTED_CONTENT]"

    @classmethod
    def sanitize_string(
        cls,
        text: str,
        source: TelemetrySource = TelemetrySource.EMAIL,
        content_id: Optional[str] = None,
    ) -> SanitizationResult:
        """
        Sanitizes a single text string, calculates taint tau, and applies spotlighting.
        """
        if not text:
            return SanitizationResult(
                clean_text="",
                taint_score=SOURCE_BASE_TAINT.get(source, 0.5),
                is_injection_detected=False,
                detected_patterns=[],
                is_spotlighted=False,
            )

        is_injection, patterns = cls.detect_prompt_injection(text)
        base_taint = SOURCE_BASE_TAINT.get(source, 0.5)

        if is_injection:
            # When injection is actively detected, taint is pinned to maximum 1.0 (no mitigation)
            final_taint = 1.0
            spotlighted = cls.spotlight_text(text, content_id=content_id)
        else:
            # Spotlighting mitigates origin risk by delta factor
            final_taint = max(0.0, min(1.0, base_taint * (1.0 - cls.DELTA_SANITIZER)))
            spotlighted = cls.spotlight_text(text, content_id=content_id)

        return SanitizationResult(
            clean_text=spotlighted,
            taint_score=round(final_taint, 3),
            is_injection_detected=is_injection,
            detected_patterns=patterns,
            is_spotlighted=True,
        )

    @classmethod
    def process_alert_payload(
        cls,
        source: TelemetrySource,
        raw_payload: Dict[str, Any],
        content_id: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], float, bool, List[str]]:
        """
        Processes an entire alert payload dictionary according to its source type.
        Returns: (sanitized_payload, taint_score, is_injection_detected, detected_patterns)
        """
        cid = content_id or str(uuid.uuid4())
        all_detected_patterns = []
        is_any_injection = False

        sanitized_payload = dict(raw_payload)

        if source == TelemetrySource.EMAIL:
            # Email bodies and subjects are high-risk untrusted text
            email_text = str(raw_payload.get("email_text") or raw_payload.get("body") or "")
            if email_text:
                res = cls.sanitize_string(email_text, source=source, content_id=cid)
                sanitized_payload["sanitized_body"] = res.clean_text
                if res.is_injection_detected:
                    is_any_injection = True
                    all_detected_patterns.extend(res.detected_patterns)

            # Assign taint
            final_taint = 1.0 if is_any_injection else round(SOURCE_BASE_TAINT[TelemetrySource.EMAIL] * (1.0 - cls.DELTA_SANITIZER), 3)

        elif source == TelemetrySource.SURICATA:
            # Inspect HTTP user-agents, URI, and signatures for hidden prompt injection
            sig = str(raw_payload.get("alert", {}).get("signature", ""))
            http_info = raw_payload.get("http", {})
            user_agent = str(http_info.get("http_user_agent", ""))
            uri = str(http_info.get("url", ""))

            combined = f"{sig} {user_agent} {uri}"
            is_any_injection, all_detected_patterns = cls.detect_prompt_injection(combined)

            if is_any_injection:
                final_taint = 1.0
                if user_agent:
                    sanitized_payload["http"]["http_user_agent"] = cls.spotlight_text(user_agent, content_id=cid)
            else:
                final_taint = SOURCE_BASE_TAINT[TelemetrySource.SURICATA]

        elif source in (TelemetrySource.WAZUH, TelemetrySource.LANL):
            # Internal authenticated sensors: structured, low baseline taint
            raw_log = str(raw_payload.get("raw_log", ""))
            if raw_log:
                is_any_injection, all_detected_patterns = cls.detect_prompt_injection(raw_log)

            if is_any_injection:
                final_taint = 1.0
                sanitized_payload["sanitized_log"] = cls.spotlight_text(raw_log, content_id=cid)
            else:
                final_taint = SOURCE_BASE_TAINT.get(source, 0.1)

        else:
            final_taint = 0.5

        return sanitized_payload, final_taint, is_any_injection, all_detected_patterns
