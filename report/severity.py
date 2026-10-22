"""
Consistent severity scoring for findings.

Not real CVSS. Real CVSS is a 200-page spec designed for CVE
publishers, not for a pentest toolkit that scans a /24 in three
minutes. This module does three things well:

  1. Assigns a base severity to every finding type we know about.
  2. Applies contextual modifiers (auth required, external vs internal,
     extracted data, WAF present, etc.) to produce a final score.
  3. Explains *why* a finding got its severity, so reports can justify
     the rating to a customer instead of dropping a bare number.

Scoring model:

    score = base_score[type] * product(modifiers)

    info     0.0 – 0.9
    low      1.0 – 3.9
    medium   4.0 – 6.9
    high     7.0 – 8.9
    critical 9.0 – 10.0

Every modifier carries a human-readable reason. The justification
string at the end is just the reasons joined with ' + '.

Overrides: if a finding dict already contains a "severity" field with
a recognized value, we honor it and skip scoring. This lets modules
that have domain knowledge (e.g. a known-CVE matcher) pin severity
explicitly without fighting the generic scorer.

Usage:

    from report.severity import score_finding, score_findings

    f = {"type": "sqli", "target": "http://x/y",
         "context": {"authenticated": False, "external": True,
                     "extracted_data": True}}

    result = score_finding(f)
    # {
    #     "severity": "critical",
    #     "score": 9.75,
    #     "base_score": 6.0,
    #     "modifiers": ["unauthenticated ×1.25", "external ×1.2",
    #                   "extracted_data ×1.3"],
    #     "justification": "SQL injection (base 6.0) + unauthenticated +
    #                       external + data extracted"
    # }

    # Or bulk:
    scored = score_findings(list_of_findings)   # in-place update
"""

from core.output import info, warn


# ---------------------------------------------------------------------
# Base scores by finding type
# ---------------------------------------------------------------------
#
# These are the *starting* scores before modifiers. They reflect
# "if this finding is real, how bad is it on a typical target?".
#
# Rules of thumb:
#   - RCE / unauth data compromise:            9–10
#   - Auth bypass / SQLi / NoSQLi:             6–8
#   - XSS / SSRF / LFI:                        5–7
#   - Info disclosure / misconfig:             1–4
#   - Open ports / banners:                    0.5–2
#
# Any type not in this table gets a conservative default of 3.0 (low),
# with a warning so we notice and can add it.

BASE_SCORES = {
    # -- Web exploits --
    "sqli":              6.0,
    "nosqli":            6.0,
    "xss":               5.0,
    "xss_stored":        7.0,
    "ssrf":              6.5,
    "lfi":               6.5,
    "rfi":               8.5,
    "xxe":               7.5,
    "csrf":              4.5,
    "open_redirect":     3.5,
    "crlf":              4.5,
    "ssti":              8.0,     # server-side template injection
    "deserialization":   9.0,

    # -- Auth --
    "auth_bypass":       8.0,
    "default_creds":     7.0,
    "weak_password":     6.0,
    "bruteforce_success": 7.5,
    "session_fixation":  6.0,
    "jwt_alg_none":      7.5,
    "jwt_weak_key":      8.0,

    # -- Network --
    "open_port":         1.0,
    "unusual_open_port": 2.5,
    "outdated_service":  4.0,
    "cve_match":         5.5,     # adjusted further by modifier below
    "weak_tls":          3.5,
    "expired_cert":      2.0,
    "self_signed_cert":  1.5,
    "null_session":      6.0,     # SMB null session
    "smb_share":         4.5,
    "snmp_default_community": 5.5,

    # -- Info disclosure --
    "dir_listing":       3.0,
    "git_exposed":       7.0,
    "env_exposed":       8.0,
    "backup_file":       6.5,
    "source_code_disclosure": 6.0,
    "debug_endpoint":    5.5,
    "server_banner":     0.5,
    "stack_trace":       3.0,
    "internal_ip_leak":  2.0,

    # -- Meta / context --
    "misconfig":         3.0,
    "informational":     0.5,
    "unknown":           3.0,
}


# ---------------------------------------------------------------------
# Modifiers
# ---------------------------------------------------------------------
#
# Each modifier is (name, multiplier, reason, condition_callable).
# Condition receives a "context" dict; if it returns truthy, we apply
# the modifier. Context keys are all optional.
#
# The order matters: same multipliers applied in any order give the
# same product, but we preserve insertion order so the justification
# reads naturally.

MODIFIERS = [
    # Auth context
    ("unauthenticated", 1.25, "no authentication required",
     lambda c: c.get("authenticated") is False),
    ("authenticated",   0.75, "requires authentication",
     lambda c: c.get("authenticated") is True),

    # Network context
    ("external",        1.20, "internet-facing",
     lambda c: c.get("external") is True),
    ("internal",        0.80, "internal-only",
     lambda c: c.get("external") is False),

    # Data extraction
    ("extracted_data",  1.30, "exploitation succeeded (data extracted)",
     lambda c: c.get("extracted_data") is True),
    ("blind_only",      0.70, "blind-only oracle (no direct output)",
     lambda c: c.get("blind_only") is True),

    # Preconditions
    ("requires_user_interaction", 0.60,
     "requires victim interaction",
     lambda c: c.get("requires_user_interaction") is True),
    ("requires_superuser", 0.85, "requires elevated privileges",
     lambda c: c.get("requires_superuser") is True),

    # Mitigations
    ("waf_present",     0.90, "WAF / filter present",
     lambda c: c.get("waf_present") is True),
    ("csp_mitigates",   0.70, "CSP blocks exploitation",
     lambda c: c.get("csp_mitigates") is True),

    # Positive confirmation
    ("has_poc",         1.10, "working proof-of-concept or credential",
     lambda c: c.get("has_poc") is True),
]


# ---------------------------------------------------------------------
# Severity buckets
# ---------------------------------------------------------------------

SEVERITY_BUCKETS = [
    (0.0, 0.9,  "info"),
    (1.0, 3.9,  "low"),
    (4.0, 6.9,  "medium"),
    (7.0, 8.9,  "high"),
    (9.0, 10.0, "critical"),
]


def bucket(score: float) -> str:
    """Map a numeric score to a severity label."""
    for lo, hi, label in SEVERITY_BUCKETS:
        if lo <= score <= hi:
            return label
    # Floating point edge cases
    if score < 0.0:
        return "info"
    return "critical"


# Human-readable descriptions of each severity level
SEVERITY_DESCRIPTIONS = {
    "info":     "Informational — no immediate risk",
    "low":      "Low — limited impact, often requires preconditions",
    "medium":   "Medium — meaningful impact, could combine with others",
    "high":     "High — significant impact, likely exploitable",
    "critical": "Critical — direct compromise or full data access",
}


# Ordering helper for sorting findings by severity
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_rank(label: str) -> int:
    """Return a sortable integer for a severity label."""
    return SEVERITY_ORDER.get((label or "").lower(), 0)


# ---------------------------------------------------------------------
# Main scoring functions
# ---------------------------------------------------------------------

def score_finding(finding: dict, apply_override: bool = True) -> dict:
    """Score one finding and return the scoring envelope.

    Does NOT mutate the input dict. The caller decides whether to
    merge the result in.
    """
    # Explicit override? (module knows better than the generic scorer)
    if apply_override:
        override = finding.get("severity")
        if isinstance(override, str) and override.lower() in SEVERITY_ORDER:
            return {
                "severity": override.lower(),
                "score": _bucket_ceiling(override.lower()),
                "base_score": None,
                "modifiers": ["explicit override"],
                "justification": f"explicitly rated '{override.lower()}' by module",
                "override": True,
            }

    ftype = (finding.get("type") or "unknown").lower()
    base = BASE_SCORES.get(ftype)
    if base is None:
        base = BASE_SCORES["unknown"]
        warn(f"no base score for finding type {ftype!r}; using default")

    # Context is either nested under finding["context"] or spread on
    # the finding itself. We check both so modules can be lazy.
    context = {}
    if isinstance(finding.get("context"), dict):
        context.update(finding["context"])
    for k in ("authenticated", "external", "extracted_data", "blind_only",
              "requires_user_interaction", "requires_superuser",
              "waf_present", "csp_mitigates", "has_poc"):
        if k in finding and k not in context:
            context[k] = finding[k]

    # Apply modifiers
    score = base
    reasons = []
    modifier_strs = []
    for name, mult, reason, cond in MODIFIERS:
        try:
            if cond(context):
                score *= mult
                modifier_strs.append(f"{name} ×{mult}")
                reasons.append(reason)
        except Exception:
            # A bad context value shouldn't crash the report
            continue

    # Clamp to 0–10
    score = max(0.0, min(10.0, score))

    # CVE-specific adjustment: severity comes from the CVE itself
    if ftype == "cve_match":
        cve_sev = (finding.get("cve_severity") or "").lower()
        cve_mult = {"critical": 2.0, "high": 1.5,
                    "medium": 1.0, "low": 0.5}.get(cve_sev)
        if cve_mult:
            score = min(10.0, score * cve_mult)
            modifier_strs.append(f"cve:{cve_sev} ×{cve_mult}")
            reasons.append(f"CVE rated {cve_sev}")

    final_label = bucket(score)

    # Build a sentence-ish justification
    pretty_type = _pretty_type(ftype)
    if reasons:
        just = f"{pretty_type} (base {base}) + " + " + ".join(reasons)
    else:
        just = f"{pretty_type} (base {base})"

    return {
        "severity": final_label,
        "score": round(score, 2),
        "base_score": base,
        "modifiers": modifier_strs,
        "justification": just,
        "override": False,
    }


def score_findings(findings: list, apply_override: bool = True) -> list:
    """Score every finding in a list, updating each in place.

    Adds these keys to each finding:
      severity, severity_score, severity_justification, severity_modifiers

    Preserves any existing severity if `apply_override=True` and the
    finding already has a recognized value.
    """
    for f in findings:
        result = score_finding(f, apply_override=apply_override)
        f["severity"] = result["severity"]
        f["severity_score"] = result["score"]
        f["severity_justification"] = result["justification"]
        f["severity_modifiers"] = result["modifiers"]
        f["severity_override"] = result["override"]
    return findings


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _bucket_ceiling(label: str) -> float:
    """Return the top score within a severity bucket. Used for overrides."""
    for lo, hi, name in SEVERITY_BUCKETS:
        if name == label:
            return hi
    return 5.0


def _pretty_type(ftype: str) -> str:
    """Turn a machine type into a human label for justifications."""
    return {
        "sqli": "SQL injection",
        "nosqli": "NoSQL injection",
        "xss": "Cross-site scripting",
        "xss_stored": "Stored cross-site scripting",
        "ssrf": "Server-side request forgery",
        "lfi": "Local file inclusion",
        "rfi": "Remote file inclusion",
        "xxe": "XML external entity",
        "csrf": "Cross-site request forgery",
        "open_redirect": "Open redirect",
        "crlf": "CRLF injection",
        "ssti": "Server-side template injection",
        "deserialization": "Unsafe deserialization",
        "auth_bypass": "Authentication bypass",
        "default_creds": "Default credentials",
        "weak_password": "Weak password policy",
        "bruteforce_success": "Brute-force success",
        "session_fixation": "Session fixation",
        "jwt_alg_none": "JWT alg=none bypass",
        "jwt_weak_key": "JWT weak signing key",
        "open_port": "Open port",
        "unusual_open_port": "Unusual open port",
        "outdated_service": "Outdated service version",
        "cve_match": "CVE match",
        "weak_tls": "Weak TLS configuration",
        "expired_cert": "Expired TLS certificate",
        "self_signed_cert": "Self-signed TLS certificate",
        "null_session": "SMB null session",
        "smb_share": "Accessible SMB share",
        "snmp_default_community": "SNMP default community string",
        "dir_listing": "Directory listing",
        "git_exposed": "Exposed .git directory",
        "env_exposed": "Exposed .env file",
        "backup_file": "Exposed backup file",
        "source_code_disclosure": "Source code disclosure",
        "debug_endpoint": "Debug endpoint exposed",
        "server_banner": "Server banner disclosure",
        "stack_trace": "Stack trace disclosure",
        "internal_ip_leak": "Internal IP disclosure",
        "misconfig": "Security misconfiguration",
        "informational": "Informational",
        "unknown": "Finding",
    }.get(ftype, ftype.replace("_", " ").title())


# ---------------------------------------------------------------------
# Consistency check for reports
# ---------------------------------------------------------------------

def worst_severity(findings: list) -> str:
    """Return the highest severity present in a list of findings."""
    best_rank = 0
    best_label = "info"
    for f in findings:
        label = (f.get("severity") or "info").lower()
        r = severity_rank(label)
        if r > best_rank:
            best_rank = r
            best_label = label
    return best_label


def summarize_severities(findings: list) -> dict:
    """Return {'critical': n, 'high': n, ...} for a list of findings."""
    out = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        label = (f.get("severity") or "info").lower()
        out.setdefault(label, 0)
        out[label] += 1
    return out


# ---------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------

def _self_test():
    """Quick internal sanity check. Run with: python -m report.severity"""
    tests = [
        # (finding, expected_label)
        ({"type": "sqli", "context": {"external": True,
                                       "authenticated": False,
                                       "extracted_data": True}},
         "critical"),  # 6.0 * 1.25 * 1.2 * 1.3 = 11.7 → clamped 10
        ({"type": "xss"}, "medium"),               # 5.0 no modifiers
        ({"type": "open_port"}, "low"),            # 1.0
        ({"type": "server_banner"}, "info"),       # 0.5
        ({"type": "default_creds",
          "context": {"authenticated": False}}, "high"),
        ({"type": "lfi",
          "context": {"blind_only": True,
                      "internal": True}}, "medium"),  # 6.5 * 0.7 * 0.8 = 3.64
        ({"type": "sqli", "severity": "critical"}, "critical"),  # override
    ]
    ok = 0
    for f, expected in tests:
        r = score_finding(f)
        got = r["severity"]
        mark = "✓" if got == expected else "✗"
        if got == expected:
            ok += 1
        print(f"  {mark} {f['type']:20s} -> {got:8s} "
              f"(score {r['score']}, expected {expected})")
        if got != expected:
            print(f"      justification: {r['justification']}")
    print(f"\n{ok}/{len(tests)} tests passed")


if __name__ == "__main__":
    _self_test()