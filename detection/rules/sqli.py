"""
sql injection detection — pattern matching against raw_payload,
username, password, and command fields. classic signature-based
approach, same idea real WAFs use at a basic level.
"""

import re

# common sqli patterns — not exhaustive, but covers the vast majority
# of automated scanner payloads we'll realistically see
SQLI_PATTERNS = [
    r"(\bOR\b|\bAND\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",   # OR 1=1
    r"UNION\s+SELECT",
    r"DROP\s+TABLE",
    r"INSERT\s+INTO",
    r"--\s*$",                                                # trailing comment
    r"';",                                                    # quote-semicolon breakout
    r"\bSLEEP\(\d+\)",                                        # time-based blind sqli
    r"\bBENCHMARK\(",
    r"xp_cmdshell",
    r"information_schema",
    r"'\s*OR\s*'1'\s*=\s*'1",
]

_compiled = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]


def check(events: list[dict]) -> dict:
    matched_payloads = []

    for event in events:
        # check every text field that could carry an injection attempt
        fields_to_check = [
            event.get("raw_payload") or "",
            event.get("username") or "",
            event.get("password") or "",
            event.get("command") or "",
        ]

        for field in fields_to_check:
            for pattern in _compiled:
                if pattern.search(field):
                    matched_payloads.append(field[:80])
                    break

    if matched_payloads:
        # sqli is a serious, deliberate attack — weight it heavily
        score = min(50, 30 + len(matched_payloads) * 5)
        return {
            "detected": True,
            "score": score,
            "reason": f"SQL injection pattern in payload: {matched_payloads[0]!r}",
        }

    return {"detected": False, "score": 0, "reason": None}
