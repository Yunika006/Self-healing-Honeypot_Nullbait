"""
command injection detection — looks for shell metacharacters and
common malicious command patterns in the 'command' field (from
the fake ssh shell) and raw_payload.
"""

import re

CMDI_PATTERNS = [
    r";\s*(rm|wget|curl|nc|bash|sh)\s",
    r"\|\s*(nc|bash|sh)\b",
    r"&&\s*(wget|curl)",
    r"\$\(.*\)",                  # command substitution $(...)
    r"`.*`",                      # backtick command substitution
    r">\s*/dev/(tcp|udp)/",       # bash reverse shell trick
    r"chmod\s+\+x",
    r"/etc/passwd",
    r"/etc/shadow",
    r"nc\s+-e\s",                 # netcat reverse shell
    r"python.*-c.*socket",
]

_compiled = [re.compile(p, re.IGNORECASE) for p in CMDI_PATTERNS]


def check(events: list[dict]) -> dict:
    matched = []

    for event in events:
        fields_to_check = [event.get("command") or "", event.get("raw_payload") or ""]
        for field in fields_to_check:
            for pattern in _compiled:
                if pattern.search(field):
                    matched.append(field[:80])
                    break

    if matched:
        score = min(45, 30 + len(matched) * 5)
        return {
            "detected": True,
            "score": score,
            "reason": f"command injection pattern detected: {matched[0]!r}",
        }

    return {"detected": False, "score": 0, "reason": None}
