"""Burp Suite DAST normaliser — FR-CTM-002.

Consumes Burp Suite REST API export findings (Burp Issue format) and
normalises them into :class:`CTEMExposure` records.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from ctem_normaliser.base import BaseNormaliser
from ctem_normaliser.models import (
    ZONE_CONSEQUENCE_FALLBACK,
    CTEMExposure,
    compute_ctem_score,
    compute_severity,
    compute_sla_deadline,
)

# ---------------------------------------------------------------------------
# Severity mapping: Burp → internal normalised severity level
# ---------------------------------------------------------------------------

# Burp severity → CTEM severity (used as original_severity)
_SEVERITY_MAP: dict[str, str] = {
    "High": "CRITICAL",
    "Medium": "HIGH",
    "Low": "MEDIUM",
    "Info": "LOW",
}

# Burp severity → exploitability level (used for consequence-weighted matrix)
_SEVERITY_EXPLOITABILITY: dict[str, str] = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Info": "low",
}

# ---------------------------------------------------------------------------
# Confidence mapping: Burp → numeric score
# ---------------------------------------------------------------------------

_CONFIDENCE_SCORE: dict[str, float] = {
    "Certain": 0.9,
    "Firm": 0.7,
    "Tentative": 0.5,
}

# ---------------------------------------------------------------------------
# OWASP-based consequence scores per vulnerability class
# ---------------------------------------------------------------------------

# Maps normalised issue-name substrings → consequence score (0.0–1.0)
_CONSEQUENCE_SCORE_MAP: list[tuple[str, float]] = [
    ("sql injection", 0.9),
    ("sqli", 0.9),
    ("remote code execution", 0.9),
    ("rce", 0.9),
    ("command injection", 0.9),
    ("xxe", 0.8),
    ("xml external entity", 0.8),
    ("ssrf", 0.8),
    ("server-side request forgery", 0.8),
    ("authentication bypass", 0.8),
    ("broken authentication", 0.8),
    ("path traversal", 0.75),
    ("directory traversal", 0.75),
    ("file inclusion", 0.75),
    ("insecure deserialisation", 0.75),
    ("deserialization", 0.75),
    ("cross-site scripting", 0.6),
    ("xss", 0.6),
    ("csrf", 0.55),
    ("cross-site request forgery", 0.55),
    ("idor", 0.65),
    ("broken access control", 0.65),
    ("information disclosure", 0.4),
    ("sensitive data exposure", 0.4),
    ("security misconfiguration", 0.35),
    ("clickjacking", 0.3),
    ("open redirect", 0.3),
]

# Default consequence score when no keyword matches
_DEFAULT_CONSEQUENCE_SCORE = 0.4

# ---------------------------------------------------------------------------
# Internal IP ranges for zone classification
# ---------------------------------------------------------------------------

_INTERNAL_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# Private-looking hostnames
_INTERNAL_HOSTNAME_PATTERNS: re.Pattern[str] = re.compile(
    r"(^localhost$"
    r"|\.local$"
    r"|\.internal$"
    r"|\.corp$"
    r"|\.lan$"
    r"|\.intranet$"
    r")",
    re.IGNORECASE,
)


def _is_internal_host(host: str) -> bool:
    """Return True if *host* resolves to an RFC-1918 / internal address."""
    # Strip port if present
    bare = host.split(":")[0]

    # Check hostname patterns first
    if _INTERNAL_HOSTNAME_PATTERNS.search(bare):
        return True

    # Attempt IP parse
    try:
        addr = ipaddress.ip_address(bare)
        return any(addr in net for net in _INTERNAL_NETWORKS)
    except ValueError:
        return False


def _classify_zone(host: str) -> str:
    """Return the asset_zone string based on host reachability."""
    if _is_internal_host(host):
        return "Zone3_Enterprise"
    return "Zone5_Internet"


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _get_consequence_score(issue_name: str) -> float:
    """Return OWASP-based consequence score for the given issue name."""
    lower = issue_name.lower()
    for keyword, score in _CONSEQUENCE_SCORE_MAP:
        if keyword in lower:
            return score
    return _DEFAULT_CONSEQUENCE_SCORE


def _consequence_score_to_category(score: float) -> str:
    """Map a numeric consequence score to a consequence category string."""
    if score >= 0.85:
        return "safety_life"
    if score >= 0.65:
        return "equipment"
    if score >= 0.45:
        return "downtime"
    return "data_loss"


def _compute_exploitability_score(
    burp_severity: str,
    confidence_score: float,
) -> float:
    """Derive a 0–1 exploitability score from Burp severity and confidence.

    Exploitability reflects both the ease of exploitation (severity proxy)
    and the analyst's certainty (confidence).
    """
    base_scores: dict[str, float] = {
        "High": 0.9,
        "Medium": 0.6,
        "Low": 0.35,
        "Info": 0.1,
    }
    base = base_scores.get(burp_severity, 0.35)
    # Weight confidence into the score: score = base * confidence_factor
    # confidence_factor: Certain(0.9)→1.0, Firm(0.7)→0.85, Tentative(0.5)→0.7
    confidence_factor = 0.7 + (confidence_score - 0.5) * 1.5
    return round(min(max(base * confidence_factor, 0.0), 1.0), 3)


def _sha256_prefix(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:length]


# ---------------------------------------------------------------------------
# Normaliser
# ---------------------------------------------------------------------------

class BurpNormaliser(BaseNormaliser):
    """Normalises Burp Suite REST API export findings (Burp Issue format)."""

    def source_name(self) -> str:
        return "burp"

    def normalise(self, raw: dict[str, Any]) -> CTEMExposure:
        issue_name: str = raw.get("issue_name", raw.get("name", ""))
        burp_severity: str = raw.get("severity", "Info")
        burp_confidence: str = raw.get("confidence", "Tentative")
        host: str = raw.get("host", "")
        path: str = raw.get("path", "/")

        # Parsed host (strip scheme if present in the host field)
        parsed_host = urlparse(host).hostname or host

        # Asset ID: sha256(host + path)
        asset_id = _sha256_prefix(f"{host}{path}")

        # Exposure key: sha256("{source_tool}:{issue_name}:{asset_id}")[:16]
        exposure_key = _sha256_prefix(f"burp:{issue_name}:{asset_id}")

        # Zone classification
        asset_zone = _classify_zone(parsed_host)

        # Consequence from zone + OWASP override
        zone_consequence = ZONE_CONSEQUENCE_FALLBACK.get(asset_zone, "data_loss")
        owasp_consequence_score = _get_consequence_score(issue_name)
        owasp_consequence = _consequence_score_to_category(owasp_consequence_score)

        # Use the more severe consequence of zone and OWASP
        _consequence_order = ["data_loss", "downtime", "equipment", "safety_life"]
        consequence = (
            owasp_consequence
            if _consequence_order.index(owasp_consequence)
            > _consequence_order.index(zone_consequence)
            else zone_consequence
        )

        # Confidence → numeric
        confidence_score: float = _CONFIDENCE_SCORE.get(burp_confidence, 0.5)

        # Exploitability
        exploitability_level = _SEVERITY_EXPLOITABILITY.get(burp_severity, "low")
        exploitability_score = _compute_exploitability_score(
            burp_severity, confidence_score
        )

        # Severity from consequence-weighted matrix
        severity = compute_severity(exploitability_level, consequence)

        # Original severity in normalised form
        original_severity = _SEVERITY_MAP.get(burp_severity, "LOW")

        # CTEM score
        ctem_score = compute_ctem_score(exploitability_score, consequence)

        # Remediation guidance: prefer remediation_background, fall back to
        # issue_background
        remediation_guidance = raw.get(
            "remediation_background", raw.get("issue_background", "")
        )

        # Description: prefer issue_background
        description = raw.get("issue_background", raw.get("remediation_background", ""))

        # Evidence URL: reconstruct from host + path when not explicitly provided
        evidence_url = raw.get("evidence_url", f"{host}{path}")

        return CTEMExposure(
            exposure_key=exposure_key,
            ts=raw.get("detected_at", datetime.now(timezone.utc).isoformat()),
            source_tool="burp",
            title=issue_name,
            description=description,
            severity=severity,
            original_severity=original_severity,
            asset_id=asset_id,
            asset_type="web_application",
            asset_zone=asset_zone,
            exploitability_score=exploitability_score,
            physical_consequence=consequence,
            ctem_score=ctem_score,
            atlas_technique=raw.get("atlas_technique", ""),
            attack_technique=raw.get("attack_technique", ""),
            threat_model_ref=raw.get("threat_model_ref", ""),
            status="Open",
            sla_deadline=compute_sla_deadline(severity),
            remediation_guidance=remediation_guidance,
            evidence_url=evidence_url,
            tenant_id=raw.get("tenant_id", ""),
        )
