"""Load and parse YAML fuzzing templates from disk.

``TemplateLoader`` is the single entry point for reading template
files. It parses YAML, constructs ``FuzzTemplate`` dataclass instances,
validates them, and resolves payload file references.

Usage::

    from sentinal_fuzz.fuzzer.template_loader import TemplateLoader

    loader = TemplateLoader()

    # Load all built-in templates
    templates = loader.load_all()

    # Load only XSS-related templates
    xss_templates = loader.load_by_tags(["xss"])

    # Load a single file
    template = loader.load_from_file("templates/custom-check.yaml")
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from sentinal_fuzz.core.models import SeverityLevel
from sentinal_fuzz.fuzzer.template_schema import FuzzTemplate, Matcher
from sentinal_fuzz.fuzzer.template_validator import validate
from sentinal_fuzz.utils.logger import get_logger

log = get_logger("template_loader")

# Built-in templates directory — resolved relative to the project root.
# The project root is 2 levels up from this file:
#   sentinal_fuzz/fuzzer/template_loader.py  →  ../../templates/
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_BUILTIN_TEMPLATES_DIR = _PROJECT_ROOT / "templates"


class TemplateLoadError(Exception):
    """Raised when a template file cannot be loaded or is invalid."""


class TemplateLoader:
    """Loads, parses, and validates YAML fuzzing templates.

    Attributes:
        templates_dir: Path to the directory containing YAML templates.
    """

    def __init__(self, templates_dir: str | Path | None = None) -> None:
        """Initialise the loader.

        Args:
            templates_dir: Override the default built-in templates directory.
                           If ``None``, uses ``<project_root>/templates/``.
        """
        if templates_dir is not None:
            self.templates_dir = Path(templates_dir).resolve()
        else:
            self.templates_dir = _BUILTIN_TEMPLATES_DIR

    # ── Public API ─────────────────────────────────────────────

    def load_from_file(self, path: str | Path) -> FuzzTemplate:
        """Load a single template from a YAML file.

        Args:
            path: Path to the YAML file (absolute or relative to CWD).

        Returns:
            A validated ``FuzzTemplate`` instance.

        Raises:
            TemplateLoadError: If the file is missing, unparseable, or invalid.
        """
        filepath = Path(path).resolve()
        if not filepath.is_file():
            raise TemplateLoadError(f"Template file not found: {filepath}")

        try:
            raw = yaml.safe_load(filepath.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise TemplateLoadError(f"YAML parse error in {filepath}: {exc}") from exc

        if not isinstance(raw, dict):
            raise TemplateLoadError(
                f"Template file must contain a YAML mapping, got {type(raw).__name__}: {filepath}"
            )

        template = self._parse_template(raw, source_path=filepath)
        self._resolve_payloads(template, base_dir=filepath.parent)
        self._validate_or_raise(template, source_path=filepath)

        return template

    def load_from_dir(self, dir_path: str | Path) -> list[FuzzTemplate]:
        """Load all YAML templates from a directory (non-recursive).

        Args:
            dir_path: Path to a directory containing ``.yaml`` / ``.yml`` files.

        Returns:
            A list of validated ``FuzzTemplate`` instances.

        Raises:
            TemplateLoadError: If the directory does not exist.
        """
        dirp = Path(dir_path).resolve()
        if not dirp.is_dir():
            raise TemplateLoadError(f"Template directory not found: {dirp}")

        templates: list[FuzzTemplate] = []
        yaml_files = sorted(
            f for f in dirp.iterdir()
            if f.is_file() and f.suffix in {".yaml", ".yml"}
        )

        for filepath in yaml_files:
            try:
                template = self.load_from_file(filepath)
                templates.append(template)
                log.debug("Loaded template: %s (%s)", template.id, filepath.name)
            except TemplateLoadError as exc:
                log.warning("Skipping invalid template %s: %s", filepath.name, exc)

        log.info("Loaded %d templates from %s", len(templates), dirp)
        return templates

    def load_by_tags(
        self,
        tags: list[str],
        *,
        match_all: bool = False,
    ) -> list[FuzzTemplate]:
        """Load templates filtered by tag.

        Args:
            tags:      Tags to filter on (e.g. ``["xss", "injection"]``).
            match_all: If True, a template must have **all** specified tags.
                       If False (default), any overlap is sufficient.

        Returns:
            Filtered list of templates.
        """
        all_templates = self.load_all()
        tag_set = {t.lower() for t in tags}

        if match_all:
            return [
                t for t in all_templates
                if tag_set.issubset(set(t.tags))
            ]
        return [
            t for t in all_templates
            if tag_set.intersection(set(t.tags))
        ]

    def load_all(self) -> list[FuzzTemplate]:
        """Load all built-in templates from the configured templates directory.

        Returns:
            A list of validated ``FuzzTemplate`` instances.
        """
        return self.load_from_dir(self.templates_dir)

    # ── Internal helpers ───────────────────────────────────────

    def _parse_template(
        self,
        raw: dict,
        source_path: Path,
    ) -> FuzzTemplate:
        """Convert a raw YAML dict into a ``FuzzTemplate`` dataclass.

        Args:
            raw:         Parsed YAML dictionary.
            source_path: Path of the source file (for error messages).

        Returns:
            A ``FuzzTemplate`` instance (not yet validated).
        """
        # Extract the info block (some templates nest metadata under 'info')
        info = raw.get("info", {})

        # Flatten: top-level keys take precedence, then info keys
        template_id = raw.get("id", info.get("id", ""))
        name = raw.get("name", info.get("name", ""))
        severity_str = raw.get("severity", info.get("severity", "info"))
        tags = raw.get("tags", info.get("tags", []))
        description = raw.get("description", info.get("description", ""))
        references = raw.get("references", info.get("references", []))

        # Parse severity
        severity = self._parse_severity(severity_str, source_path)

        # Parse target_params — default to ["query", "form"]
        target_params = raw.get("target_params", ["query", "form"])

        # Parse payloads — can be inline list or file path string
        payloads = self._parse_payloads(raw, source_path)

        # Parse matchers
        matchers = self._parse_matchers(raw, source_path)

        # Scalar fields
        matchers_condition = raw.get("matchers_condition", "or")
        stop_on_first_match = raw.get("stop_on_first_match", True)
        cwe = raw.get("cwe", info.get("cwe", ""))
        owasp = raw.get("owasp", info.get("owasp", ""))
        remediation = raw.get("remediation", info.get("remediation", ""))

        return FuzzTemplate(
            id=template_id,
            name=name,
            severity=severity,
            tags=tags,
            description=description,
            references=references,
            target_params=target_params,
            payloads=payloads,
            matchers=matchers,
            matchers_condition=matchers_condition,
            stop_on_first_match=stop_on_first_match,
            cwe=cwe,
            owasp=owasp,
            remediation=remediation,
        )

    def _parse_severity(self, value: str, source_path: Path) -> SeverityLevel:
        """Parse a severity string into a ``SeverityLevel`` enum member."""
        value_lower = str(value).lower().strip()
        try:
            return SeverityLevel(value_lower)
        except ValueError:
            log.warning(
                "Unknown severity '%s' in %s, defaulting to INFO.",
                value,
                source_path.name,
            )
            return SeverityLevel.INFO

    def _parse_payloads(
        self,
        raw: dict,
        source_path: Path,
    ) -> list[str] | str:
        """Extract payloads from the raw YAML dict.

        Handles three layouts:
        1. Top-level ``payloads`` key with inline list.
        2. Top-level ``payloads`` key with a file path string.
        3. Nested under ``requests[0].payloads`` (legacy format).

        Args:
            raw:         Parsed YAML dictionary.
            source_path: Path of the source file (for error messages).

        Returns:
            Either a list of payload strings or a file path string.
        """
        # Direct top-level payloads
        payloads = raw.get("payloads")
        if payloads is not None:
            return payloads

        # Legacy format: requests[0].payloads
        requests = raw.get("requests")
        if isinstance(requests, list) and requests:
            first_req = requests[0]
            if isinstance(first_req, dict):
                req_payloads = first_req.get("payloads")
                if req_payloads is not None:
                    return req_payloads

        # No payloads found — could be a passive template
        return []

    def _parse_matchers(
        self,
        raw: dict,
        source_path: Path,
    ) -> list[Matcher]:
        """Extract and parse matchers from the raw YAML dict.

        Handles both top-level ``matchers`` and legacy
        ``requests[0].matchers`` formats.

        Args:
            raw:         Parsed YAML dictionary.
            source_path: Path of the source file (for error messages).

        Returns:
            List of ``Matcher`` instances.
        """
        matchers_raw = raw.get("matchers")

        # Legacy: requests[0].matchers
        if matchers_raw is None:
            requests = raw.get("requests")
            if isinstance(requests, list) and requests:
                first_req = requests[0]
                if isinstance(first_req, dict):
                    matchers_raw = first_req.get("matchers")

        if not isinstance(matchers_raw, list):
            return []

        matchers: list[Matcher] = []
        for m in matchers_raw:
            if not isinstance(m, dict):
                log.warning("Skipping non-dict matcher in %s", source_path.name)
                continue
            matchers.append(self._build_matcher(m))

        return matchers

    def _build_matcher(self, m: dict) -> Matcher:
        """Build a ``Matcher`` dataclass from a raw dict."""
        return Matcher(
            type=m.get("type", "word"),
            part=m.get("part", "body"),
            words=m.get("words", []),
            regex=m.get("regex", []),
            status=m.get("status", []),
            headers=m.get("headers", {}),
            condition=m.get("condition", "or"),
            negative=m.get("negative", False),
            threshold_ms=m.get("threshold_ms", 0),
            size_min=m.get("size_min", 0),
            size_max=m.get("size_max", 0),
        )

    def _resolve_payloads(
        self,
        template: FuzzTemplate,
        base_dir: Path,
    ) -> None:
        """If payloads is a file path string, load the file contents.

        The file is expected to have one payload per line. Blank lines
        and lines starting with ``#`` are skipped.

        Args:
            template: The template whose payloads may need resolving.
            base_dir: Directory of the template file (for relative paths).
        """
        if not isinstance(template.payloads, str):
            return

        payload_path_str = template.payloads.strip()
        if not payload_path_str:
            return

        # Resolve relative to template file, then try project root
        payload_path = Path(payload_path_str)
        candidates = [
            base_dir / payload_path,
            _PROJECT_ROOT / payload_path,
            payload_path.resolve(),
        ]

        resolved: Path | None = None
        for candidate in candidates:
            if candidate.is_file():
                resolved = candidate
                break

        if resolved is None:
            log.warning(
                "Payload file not found for template '%s': %s "
                "(searched %s)",
                template.id,
                payload_path_str,
                ", ".join(str(c) for c in candidates),
            )
            template.payloads = []
            return

        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
        template.payloads = [
            line for line in lines
            if line.strip() and not line.strip().startswith("#")
        ]

        log.debug(
            "Loaded %d payloads from %s for template '%s'",
            len(template.payloads),
            resolved.name,
            template.id,
        )

    def _validate_or_raise(
        self,
        template: FuzzTemplate,
        source_path: Path,
    ) -> None:
        """Run validation and raise on errors.

        Args:
            template:    The template to validate.
            source_path: File path for the error message.

        Raises:
            TemplateLoadError: If validation produces any errors.
        """
        errors = validate(template)
        if errors:
            error_list = "\n  • ".join(errors)
            raise TemplateLoadError(
                f"Validation failed for {source_path.name}:\n  • {error_list}"
            )
