"""AGY v2.28.0 Pre-Prompt Hook Inspector for agy-golden-stack.

REQ-BUS-PROMPT-01: Provides sub-5ms pre-prompt secret redaction with deterministic
DPAPI tags and intelligent execution mode routing (fold_in_process vs spawn_subagent).
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from re import Pattern
from typing import Any

_CREDENTIAL_PATTERN: Pattern[str] = re.compile(
    r"(?:AIza[0-9A-Za-z_-]{15,}"
    r"|ghp_[0-9A-Za-z]{20,}"
    r"|sk-[0-9A-Za-z_-]{20,}"
    r"|__Secure-1PSID=[^\s;,\"']+)"
)

_SUBAGENT_TRIGGER_PATTERN: Pattern[str] = re.compile(
    r"(?:/teamwork|\bteamwork\b|\bparallel\s+branches\b|\bagile\s+v\b"
    r"|\btest-designer\b|>\s*500(?:-|\s+)lines?\b)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class UserPromptInspection:
    """@requirement("REQ-BUS-PROMPT-01")
    Immutable result of pre-prompt inspection, secret sanitization, and routing.
    """

    allowed: bool
    sanitized_message: str
    redacted_secrets_count: int
    redacted_tags: list[str]
    recommended_execution_mode: str
    latency_ms: float


class UserPromptHookInspector:
    """@requirement("REQ-BUS-PROMPT-01")
    Pre-Prompt Hook inspector enforcing DPAPI credential redaction and subagent routing.
    """

    def inspect_user_message(
        self,
        payload: Mapping[str, Any],
    ) -> UserPromptInspection:
        """@requirement("REQ-BUS-PROMPT-01")
        Inspect a user prompt payload, redact inline credentials, and determine execution mode.
        """
        t0 = time.perf_counter()

        if not isinstance(payload, Mapping):
            raw_val: Any = ""
            estimated_lines = 0
        else:
            raw_val = (
                payload.get("user_message")
                or payload.get("prompt")
                or payload.get("message")
                or ""
            )
            try:
                estimated_lines = int(payload.get("estimated_context_lines", 0) or 0)
            except (TypeError, ValueError):
                estimated_lines = 0

        raw_prompt = str(raw_val) if raw_val else ""
        redacted_tags: list[str] = []

        def _replace_match(match: re.Match[str]) -> str:
            secret = match.group(0)
            digest12 = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]
            tag = f"[REDACTED_DPAPI:{digest12}]"
            redacted_tags.append(tag)
            return tag

        sanitized_message = (
            _CREDENTIAL_PATTERN.sub(_replace_match, raw_prompt)
            if raw_prompt
            else ""
        )

        if estimated_lines > 500 or (
            raw_prompt and _SUBAGENT_TRIGGER_PATTERN.search(raw_prompt) is not None
        ):
            mode = "spawn_subagent"
        else:
            mode = "fold_in_process"

        latency_ms = (time.perf_counter() - t0) * 1000.0

        return UserPromptInspection(
            allowed=True,
            sanitized_message=sanitized_message,
            redacted_secrets_count=len(redacted_tags),
            redacted_tags=redacted_tags,
            recommended_execution_mode=mode,
            latency_ms=latency_ms,
        )
