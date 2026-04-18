"""Deduplicates findings produced by the fuzzing engine.

After a full scan, many templates can fire on the same parameter with
different payloads, producing duplicate findings.  This module collapses
them down to the most relevant representative per group.

Usage::

    from sentinal_fuzz.fuzzer.deduplicator import deduplicate

    unique_findings = deduplicate(raw_findings)
"""

from __future__ import annotations

from sentinal_fuzz.core.models import Finding
from sentinal_fuzz.utils.logger import get_logger

log = get_logger("dedup")


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings, keeping the highest-confidence instance.

    Deduplication rules:

    1. **Same vulnerability on same parameter**: Group by
       ``(template_id, url, parameter)`` — keep the finding with the
       highest confidence score.

    2. **Header / passive findings**: Group by ``template_id`` alone —
       missing-CSP only needs to be reported once per scan, not per page.

    Args:
        findings: Raw list of findings from the fuzzing engine.

    Returns:
        Deduplicated list, smallest possible.
    """
    if not findings:
        return []

    # Separate passive (header/exposure) from active findings
    passive: list[Finding] = []
    active: list[Finding] = []

    for f in findings:
        if _is_passive_finding(f):
            passive.append(f)
        else:
            active.append(f)

    # ── Deduplicate active findings ────────────────────────────
    # Key: (template_id, url, parameter) → best finding
    active_groups: dict[tuple[str, str, str], Finding] = {}
    for f in active:
        key = (f.template_id, f.url, f.parameter)
        existing = active_groups.get(key)
        if existing is None or f.confidence > existing.confidence:
            active_groups[key] = f

    # ── Deduplicate passive findings ───────────────────────────
    # Key: template_id → best finding (one per vuln type per scan)
    passive_groups: dict[str, Finding] = {}
    for f in passive:
        existing = passive_groups.get(f.template_id)
        if existing is None or f.confidence > existing.confidence:
            passive_groups[f.template_id] = f

    result = list(active_groups.values()) + list(passive_groups.values())

    deduped_count = len(findings) - len(result)
    if deduped_count > 0:
        log.info(
            "Deduplicated %d findings → %d unique (%d removed)",
            len(findings), len(result), deduped_count,
        )

    return result


def _is_passive_finding(finding: Finding) -> bool:
    """Determine if a finding comes from a passive (no-payload) check.

    Passive findings are identified by:
    - Template IDs associated with header/exposure checks.
    - Findings with the payload "(passive check)".
    - Findings with parameter "n/a".
    """
    passive_template_ids = {
        "security-headers",
        "sensitive-exposure",
        "missing-csp",
        "missing-hsts",
        "missing-x-frame-options",
        "missing-x-content-type-options",
        "missing-referrer-policy",
        "sensitive-data-exposure",
        "server-version-disclosure",
        "api-key-exposure",
        "stack-trace-exposure",
    }

    if finding.template_id in passive_template_ids:
        return True
    if finding.payload == "(passive check)":
        return True
    if finding.parameter == "n/a":
        return True
    return False
