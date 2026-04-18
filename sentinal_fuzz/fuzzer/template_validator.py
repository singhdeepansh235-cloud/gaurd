"""Validate FuzzTemplate instances for correctness.

The validator catches configuration errors *before* a scan begins,
giving the user actionable error messages about their template files.

Usage::

    from sentinal_fuzz.fuzzer.template_validator import validate

    errors = validate(template)
    if errors:
        for err in errors:
            print(f"  ✗ {err}")
"""

from __future__ import annotations

import re

from sentinal_fuzz.core.models import SeverityLevel
from sentinal_fuzz.fuzzer.template_schema import (
    VALID_CONDITIONS,
    VALID_MATCHER_PARTS,
    VALID_MATCHER_TYPES,
    VALID_TARGET_PARAMS,
    FuzzTemplate,
    Matcher,
)


def validate(template: FuzzTemplate) -> list[str]:
    """Validate a ``FuzzTemplate`` and return a list of error strings.

    An empty list means the template is valid and ready for use.

    Checks performed:
    - ``id`` is non-empty and contains no spaces.
    - ``severity`` is a valid ``SeverityLevel`` member.
    - At least one matcher is present.
    - Payloads are provided (list or file path), unless the template is passive.
    - All regex patterns compile successfully.
    - Tags are lowercase.
    - Matcher types and parts are from the allowed set.
    - Conditions are either ``"or"`` or ``"and"``.
    - Target params are from the allowed set.

    Args:
        template: The template to validate.

    Returns:
        A list of human-readable error strings. Empty if valid.
    """
    errors: list[str] = []

    # ── id ──────────────────────────────────────────────────────
    if not template.id:
        errors.append("'id' is required and must not be empty.")
    elif " " in template.id:
        errors.append(f"'id' must not contain spaces: '{template.id}'.")
    elif not re.match(r"^[a-zA-Z0-9_-]+$", template.id):
        errors.append(
            f"'id' should only contain alphanumeric characters, hyphens, "
            f"and underscores: '{template.id}'."
        )

    # ── name ────────────────────────────────────────────────────
    if not template.name:
        errors.append("'name' is required and must not be empty.")

    # ── severity ────────────────────────────────────────────────
    if not isinstance(template.severity, SeverityLevel):
        errors.append(
            f"'severity' must be a valid SeverityLevel, got: '{template.severity}'."
        )

    # ── matchers ────────────────────────────────────────────────
    if not template.matchers:
        errors.append("At least one matcher is required.")
    else:
        for i, matcher in enumerate(template.matchers):
            errors.extend(_validate_matcher(matcher, index=i))

    # ── matchers_condition ──────────────────────────────────────
    if template.matchers_condition not in VALID_CONDITIONS:
        errors.append(
            f"'matchers_condition' must be 'or' or 'and', "
            f"got: '{template.matchers_condition}'."
        )

    # ── payloads ────────────────────────────────────────────────
    if isinstance(template.payloads, str):
        # File path reference — must not be empty
        if not template.payloads.strip():
            errors.append("'payloads' file path is empty.")
    elif isinstance(template.payloads, list):
        # Inline payloads — allowed to be empty for passive templates
        pass
    else:
        errors.append(
            f"'payloads' must be a list of strings or a file path string, "
            f"got: {type(template.payloads).__name__}."
        )

    # ── target_params ───────────────────────────────────────────
    for param in template.target_params:
        if param not in VALID_TARGET_PARAMS:
            errors.append(
                f"Invalid target_param '{param}'. "
                f"Must be one of: {sorted(VALID_TARGET_PARAMS)}."
            )

    # ── tags ────────────────────────────────────────────────────
    for tag in template.tags:
        if tag != tag.lower():
            errors.append(
                f"Tag '{tag}' must be lowercase. Use '{tag.lower()}' instead."
            )
        if " " in tag:
            errors.append(f"Tag '{tag}' must not contain spaces.")

    return errors


def _validate_matcher(matcher: Matcher, index: int) -> list[str]:
    """Validate a single matcher within a template.

    Args:
        matcher: The matcher to validate.
        index:   Zero-based position of this matcher in the matchers list.

    Returns:
        A list of error strings for this matcher.
    """
    prefix = f"matchers[{index}]"
    errors: list[str] = []

    # ── type ────────────────────────────────────────────────────
    if matcher.type not in VALID_MATCHER_TYPES:
        errors.append(
            f"{prefix}: 'type' must be one of {sorted(VALID_MATCHER_TYPES)}, "
            f"got: '{matcher.type}'."
        )

    # ── part ────────────────────────────────────────────────────
    if matcher.part not in VALID_MATCHER_PARTS:
        errors.append(
            f"{prefix}: 'part' must be one of {sorted(VALID_MATCHER_PARTS)}, "
            f"got: '{matcher.part}'."
        )

    # ── condition ───────────────────────────────────────────────
    if matcher.condition not in VALID_CONDITIONS:
        errors.append(
            f"{prefix}: 'condition' must be 'or' or 'and', "
            f"got: '{matcher.condition}'."
        )

    # ── type-specific validation ────────────────────────────────
    if matcher.type == "word" and not matcher.words:
        errors.append(f"{prefix}: type='word' requires at least one entry in 'words'.")

    if matcher.type == "regex":
        if not matcher.regex:
            errors.append(
                f"{prefix}: type='regex' requires at least one entry in 'regex'."
            )
        for j, pattern in enumerate(matcher.regex):
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(
                    f"{prefix}: regex[{j}] is invalid — {exc}: '{pattern}'."
                )

    if matcher.type == "status" and not matcher.status:
        errors.append(
            f"{prefix}: type='status' requires at least one entry in 'status'."
        )

    if matcher.type == "timing" and matcher.threshold_ms <= 0:
        errors.append(
            f"{prefix}: type='timing' requires 'threshold_ms' > 0, "
            f"got: {matcher.threshold_ms}."
        )

    if matcher.type == "header" and not matcher.headers:
        errors.append(
            f"{prefix}: type='header' requires at least one entry in 'headers'."
        )

    if matcher.type == "size":
        if matcher.size_min <= 0 and matcher.size_max <= 0:
            errors.append(
                f"{prefix}: type='size' requires 'size_min' > 0 and/or 'size_max' > 0."
            )

    return errors
