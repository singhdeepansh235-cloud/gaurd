"""Tests for the YAML template system — schema, validator, and loader.

Covers:
- Loading every built-in template validates without errors
- Matcher-level validation rules
- Tag-based filtering
- Payload file resolution
- Edge cases (malformed YAML, missing fields, invalid regex)
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from sentinal_fuzz.core.models import SeverityLevel
from sentinal_fuzz.fuzzer.template_loader import TemplateLoadError, TemplateLoader
from sentinal_fuzz.fuzzer.template_schema import (
    VALID_CONDITIONS,
    VALID_MATCHER_PARTS,
    VALID_MATCHER_TYPES,
    VALID_TARGET_PARAMS,
    FuzzTemplate,
    Matcher,
)
from sentinal_fuzz.fuzzer.template_validator import validate

# ── Paths ──────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = PROJECT_ROOT / "templates"

# All built-in template YAML files
BUILTIN_TEMPLATE_FILES = sorted(TEMPLATES_DIR.glob("*.yaml"))


# ═══════════════════════════════════════════════════════════════════
# Schema Tests
# ═══════════════════════════════════════════════════════════════════


class TestFuzzTemplateSchema:
    """Test the FuzzTemplate and Matcher dataclass defaults."""

    def test_minimal_template(self):
        """A template with only required fields is constructable."""
        t = FuzzTemplate(
            id="test-minimal",
            name="Minimal Test",
            severity=SeverityLevel.INFO,
            matchers=[Matcher(type="word", part="body", words=["test"])],
        )
        assert t.id == "test-minimal"
        assert t.stop_on_first_match is True
        assert t.matchers_condition == "or"

    def test_payload_list_property_with_list(self):
        """payload_list returns the inline list when payloads is a list."""
        t = FuzzTemplate(
            id="test",
            name="Test",
            severity=SeverityLevel.INFO,
            payloads=["a", "b", "c"],
            matchers=[Matcher(type="word", part="body", words=["x"])],
        )
        assert t.payload_list == ["a", "b", "c"]

    def test_payload_list_property_with_string(self):
        """payload_list returns empty when payloads is a file path string."""
        t = FuzzTemplate(
            id="test",
            name="Test",
            severity=SeverityLevel.INFO,
            payloads="some/file.txt",
            matchers=[Matcher(type="word", part="body", words=["x"])],
        )
        assert t.payload_list == []

    def test_is_passive_no_payloads(self):
        """is_passive returns True when payload list is empty."""
        t = FuzzTemplate(
            id="test",
            name="Test",
            severity=SeverityLevel.INFO,
            payloads=[],
            matchers=[Matcher(type="word", part="body", words=["x"])],
        )
        assert t.is_passive is True

    def test_is_passive_with_payloads(self):
        """is_passive returns False when payloads exist."""
        t = FuzzTemplate(
            id="test",
            name="Test",
            severity=SeverityLevel.INFO,
            payloads=["<script>alert(1)</script>"],
            matchers=[Matcher(type="word", part="body", words=["x"])],
        )
        assert t.is_passive is False

    def test_default_target_params(self):
        """Default target_params are query and form."""
        t = FuzzTemplate(id="t", name="T", severity=SeverityLevel.INFO)
        assert t.target_params == ["query", "form"]

    def test_matcher_defaults(self):
        """Matcher defaults to type=word, part=body, condition=or."""
        m = Matcher()
        assert m.type == "word"
        assert m.part == "body"
        assert m.condition == "or"
        assert m.negative is False
        assert m.threshold_ms == 0

    def test_valid_constants(self):
        """Sanity check that constant sets contain expected values."""
        assert "word" in VALID_MATCHER_TYPES
        assert "regex" in VALID_MATCHER_TYPES
        assert "timing" in VALID_MATCHER_TYPES
        assert "body" in VALID_MATCHER_PARTS
        assert "header" in VALID_MATCHER_PARTS
        assert "query" in VALID_TARGET_PARAMS
        assert "or" in VALID_CONDITIONS
        assert "and" in VALID_CONDITIONS


# ═══════════════════════════════════════════════════════════════════
# Validator Tests
# ═══════════════════════════════════════════════════════════════════


class TestTemplateValidator:
    """Test the validate() function against various template configurations."""

    def _make_valid_template(self, **overrides) -> FuzzTemplate:
        """Create a valid template with optional overrides."""
        defaults = dict(
            id="test-valid",
            name="Valid Test Template",
            severity=SeverityLevel.HIGH,
            tags=["test", "injection"],
            payloads=["payload1"],
            matchers=[Matcher(type="word", part="body", words=["match"])],
        )
        defaults.update(overrides)
        return FuzzTemplate(**defaults)

    def test_valid_template_no_errors(self):
        """A properly configured template passes validation."""
        t = self._make_valid_template()
        errors = validate(t)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_empty_id(self):
        """Empty id produces an error."""
        t = self._make_valid_template(id="")
        errors = validate(t)
        assert any("'id' is required" in e for e in errors)

    def test_id_with_spaces(self):
        """Spaces in the id produce an error."""
        t = self._make_valid_template(id="bad id")
        errors = validate(t)
        assert any("must not contain spaces" in e for e in errors)

    def test_id_with_special_chars(self):
        """Special characters (besides hyphen/underscore) produce an error."""
        t = self._make_valid_template(id="bad!@#id")
        errors = validate(t)
        assert any("alphanumeric" in e for e in errors)

    def test_empty_name(self):
        """Empty name produces an error."""
        t = self._make_valid_template(name="")
        errors = validate(t)
        assert any("'name' is required" in e for e in errors)

    def test_no_matchers(self):
        """Template with no matchers produces an error."""
        t = self._make_valid_template(matchers=[])
        errors = validate(t)
        assert any("At least one matcher" in e for e in errors)

    def test_invalid_matchers_condition(self):
        """matchers_condition not 'or'/'and' produces an error."""
        t = self._make_valid_template(matchers_condition="xor")
        errors = validate(t)
        assert any("matchers_condition" in e for e in errors)

    def test_uppercase_tag_error(self):
        """Tags with uppercase characters produce an error."""
        t = self._make_valid_template(tags=["XSS", "Injection"])
        errors = validate(t)
        assert any("XSS" in e and "lowercase" in e for e in errors)

    def test_tag_with_spaces_error(self):
        """Tags containing spaces produce an error."""
        t = self._make_valid_template(tags=["sql injection"])
        errors = validate(t)
        assert any("must not contain spaces" in e for e in errors)

    def test_invalid_target_param(self):
        """Invalid target param value produces an error."""
        t = self._make_valid_template(target_params=["query", "invalid_param"])
        errors = validate(t)
        assert any("invalid_param" in e for e in errors)

    def test_word_matcher_needs_words(self):
        """type=word with empty words list produces an error."""
        t = self._make_valid_template(
            matchers=[Matcher(type="word", part="body", words=[])]
        )
        errors = validate(t)
        assert any("'words'" in e for e in errors)

    def test_regex_matcher_needs_regex(self):
        """type=regex with empty regex list produces an error."""
        t = self._make_valid_template(
            matchers=[Matcher(type="regex", part="body", regex=[])]
        )
        errors = validate(t)
        assert any("'regex'" in e for e in errors)

    def test_invalid_regex_pattern(self):
        """Invalid regex patterns produce a compile error."""
        t = self._make_valid_template(
            matchers=[Matcher(type="regex", part="body", regex=["[invalid"])]
        )
        errors = validate(t)
        assert any("invalid" in e.lower() for e in errors)

    def test_valid_regex_passes(self):
        """Valid regex patterns pass validation."""
        t = self._make_valid_template(
            matchers=[Matcher(type="regex", part="body", regex=[r"SQL syntax.*?MySQL"])]
        )
        errors = validate(t)
        assert errors == []

    def test_status_matcher_needs_status(self):
        """type=status with empty status list produces an error."""
        t = self._make_valid_template(
            matchers=[Matcher(type="status", part="status", status=[])]
        )
        errors = validate(t)
        assert any("'status'" in e for e in errors)

    def test_timing_matcher_needs_threshold(self):
        """type=timing with threshold_ms=0 produces an error."""
        t = self._make_valid_template(
            matchers=[Matcher(type="timing", part="response_time", threshold_ms=0)]
        )
        errors = validate(t)
        assert any("threshold_ms" in e for e in errors)

    def test_timing_matcher_valid(self):
        """type=timing with positive threshold passes."""
        t = self._make_valid_template(
            matchers=[Matcher(type="timing", part="response_time", threshold_ms=5000)]
        )
        errors = validate(t)
        assert errors == []

    def test_header_matcher_needs_headers(self):
        """type=header with empty headers dict produces an error."""
        t = self._make_valid_template(
            matchers=[Matcher(type="header", part="header", headers={})]
        )
        errors = validate(t)
        assert any("'headers'" in e for e in errors)

    def test_size_matcher_needs_limits(self):
        """type=size with no min/max produces an error."""
        t = self._make_valid_template(
            matchers=[Matcher(type="size", part="body", size_min=0, size_max=0)]
        )
        errors = validate(t)
        assert any("size_min" in e or "size_max" in e for e in errors)

    def test_size_matcher_valid(self):
        """type=size with positive limits passes."""
        t = self._make_valid_template(
            matchers=[Matcher(type="size", part="body", size_min=100)]
        )
        errors = validate(t)
        assert errors == []

    def test_invalid_matcher_type(self):
        """Unknown matcher type produces an error."""
        t = self._make_valid_template(
            matchers=[Matcher(type="unknown", part="body")]
        )
        errors = validate(t)
        assert any("'type'" in e for e in errors)

    def test_invalid_matcher_part(self):
        """Unknown matcher part produces an error."""
        t = self._make_valid_template(
            matchers=[Matcher(type="word", part="invalid_part", words=["x"])]
        )
        errors = validate(t)
        assert any("'part'" in e for e in errors)

    def test_invalid_matcher_condition(self):
        """Invalid matcher condition produces an error."""
        t = self._make_valid_template(
            matchers=[Matcher(type="word", part="body", words=["x"], condition="xor")]
        )
        errors = validate(t)
        assert any("'condition'" in e for e in errors)

    def test_passive_template_no_payload_errors(self):
        """Passive templates (empty payload list) pass validation."""
        t = self._make_valid_template(
            payloads=[],
            matchers=[
                Matcher(type="header", part="header", negative=True,
                        headers={"X-Frame-Options": "."})
            ],
        )
        errors = validate(t)
        assert errors == []


# ═══════════════════════════════════════════════════════════════════
# Loader Tests
# ═══════════════════════════════════════════════════════════════════


class TestTemplateLoader:
    """Test the TemplateLoader class."""

    @pytest.fixture
    def loader(self) -> TemplateLoader:
        """Loader pointed at the built-in templates directory."""
        return TemplateLoader(templates_dir=TEMPLATES_DIR)

    # ── Load all built-in templates ────────────────────────────

    def test_load_all_returns_templates(self, loader: TemplateLoader):
        """load_all() returns a non-empty list of templates."""
        templates = loader.load_all()
        assert len(templates) > 0, "Expected at least one built-in template"

    def test_load_all_template_count(self, loader: TemplateLoader):
        """All expected YAML files in templates/ are loaded."""
        templates = loader.load_all()
        yaml_count = len(BUILTIN_TEMPLATE_FILES)
        assert len(templates) == yaml_count, (
            f"Expected {yaml_count} templates but loaded {len(templates)}. "
            f"YAML files: {[f.name for f in BUILTIN_TEMPLATE_FILES]}"
        )

    @pytest.mark.parametrize(
        "template_file",
        BUILTIN_TEMPLATE_FILES,
        ids=[f.stem for f in BUILTIN_TEMPLATE_FILES],
    )
    def test_each_builtin_template_validates(
        self,
        loader: TemplateLoader,
        template_file: Path,
    ):
        """Every built-in YAML template loads and passes validation."""
        template = loader.load_from_file(template_file)
        errors = validate(template)
        assert errors == [], (
            f"Template '{template_file.name}' has validation errors:\n"
            + "\n".join(f"  • {e}" for e in errors)
        )

    @pytest.mark.parametrize(
        "template_file",
        BUILTIN_TEMPLATE_FILES,
        ids=[f.stem for f in BUILTIN_TEMPLATE_FILES],
    )
    def test_each_builtin_has_required_fields(
        self,
        loader: TemplateLoader,
        template_file: Path,
    ):
        """Every built-in template has id, name, severity, and at least one matcher."""
        template = loader.load_from_file(template_file)
        assert template.id, f"{template_file.name}: missing id"
        assert template.name, f"{template_file.name}: missing name"
        assert isinstance(template.severity, SeverityLevel), (
            f"{template_file.name}: invalid severity"
        )
        assert len(template.matchers) > 0, (
            f"{template_file.name}: no matchers"
        )

    # ── Load from file ─────────────────────────────────────────

    def test_load_from_file_missing(self, loader: TemplateLoader):
        """Loading a non-existent file raises TemplateLoadError."""
        with pytest.raises(TemplateLoadError, match="not found"):
            loader.load_from_file("nonexistent.yaml")

    def test_load_from_file_invalid_yaml(self, loader: TemplateLoader, tmp_path: Path):
        """Loading invalid YAML raises TemplateLoadError."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("{{invalid yaml: [", encoding="utf-8")
        with pytest.raises(TemplateLoadError, match="YAML parse error"):
            loader.load_from_file(bad_file)

    def test_load_from_file_non_dict_yaml(self, loader: TemplateLoader, tmp_path: Path):
        """Loading YAML that isn't a mapping raises TemplateLoadError."""
        bad_file = tmp_path / "list.yaml"
        bad_file.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(TemplateLoadError, match="YAML mapping"):
            loader.load_from_file(bad_file)

    def test_load_from_file_validation_error(self, tmp_path: Path):
        """Loading a YAML file with missing required fields raises TemplateLoadError."""
        # No matchers, no name → should fail validation
        bad_template = tmp_path / "bad-template.yaml"
        bad_template.write_text(textwrap.dedent("""\
            id: bad-template
            severity: high
        """), encoding="utf-8")
        loader = TemplateLoader(templates_dir=tmp_path)
        with pytest.raises(TemplateLoadError, match="Validation failed"):
            loader.load_from_file(bad_template)

    # ── Load from directory ────────────────────────────────────

    def test_load_from_dir_missing(self, loader: TemplateLoader):
        """Loading from a non-existent directory raises TemplateLoadError."""
        with pytest.raises(TemplateLoadError, match="not found"):
            loader.load_from_dir("/nonexistent/dir")

    def test_load_from_dir_empty(self, tmp_path: Path):
        """Loading from an empty directory returns an empty list."""
        loader = TemplateLoader(templates_dir=tmp_path)
        templates = loader.load_from_dir(tmp_path)
        assert templates == []

    def test_load_from_dir_skips_non_yaml(self, tmp_path: Path):
        """Non-yaml files in the directory are skipped."""
        # Create a .txt file that should be ignored
        (tmp_path / "readme.txt").write_text("not a template", encoding="utf-8")
        # Create a valid YAML template
        (tmp_path / "valid.yaml").write_text(textwrap.dedent("""\
            id: valid-test
            name: Valid Test
            severity: info
            tags: [test]
            payloads: []
            matchers:
              - type: word
                part: body
                words: ["test"]
        """), encoding="utf-8")
        loader = TemplateLoader(templates_dir=tmp_path)
        templates = loader.load_from_dir(tmp_path)
        assert len(templates) == 1
        assert templates[0].id == "valid-test"

    # ── Tag-based filtering ────────────────────────────────────

    def test_load_by_tags_single(self, loader: TemplateLoader):
        """load_by_tags with a single tag returns matching templates."""
        templates = loader.load_by_tags(["xss"])
        assert len(templates) >= 1
        assert all("xss" in t.tags for t in templates)

    def test_load_by_tags_multiple_any(self, loader: TemplateLoader):
        """load_by_tags with multiple tags (any match) returns union."""
        templates = loader.load_by_tags(["xss", "sqli"])
        assert len(templates) >= 2
        assert all(
            "xss" in t.tags or "sqli" in t.tags
            for t in templates
        )

    def test_load_by_tags_match_all(self, loader: TemplateLoader):
        """load_by_tags with match_all=True requires all tags."""
        templates = loader.load_by_tags(["injection", "owasp-a03"], match_all=True)
        for t in templates:
            assert "injection" in t.tags
            assert "owasp-a03" in t.tags

    def test_load_by_tags_no_match(self, loader: TemplateLoader):
        """load_by_tags with a nonsense tag returns empty list."""
        templates = loader.load_by_tags(["definitely-not-a-real-tag-xyz"])
        assert templates == []

    def test_load_by_tags_case_insensitive(self, loader: TemplateLoader):
        """Tags are lowercased before matching."""
        templates = loader.load_by_tags(["XSS"])
        assert len(templates) >= 1

    # ── Payload file resolution ────────────────────────────────

    def test_payload_file_resolved(self, loader: TemplateLoader):
        """Templates with file-path payloads get resolved to actual payload lists."""
        templates = loader.load_all()
        xss_templates = [t for t in templates if t.id == "xss-reflected"]
        assert len(xss_templates) == 1

        xss = xss_templates[0]
        # Payloads should be resolved from templates/payloads/xss.txt
        assert isinstance(xss.payloads, list)
        assert len(xss.payloads) > 10, (
            f"Expected many payloads loaded from file, got {len(xss.payloads)}"
        )

    def test_inline_payloads_preserved(self, loader: TemplateLoader):
        """Templates with inline payloads keep them as-is."""
        templates = loader.load_all()
        time_templates = [t for t in templates if t.id == "sqli-time"]
        assert len(time_templates) == 1

        sqli_time = time_templates[0]
        assert isinstance(sqli_time.payloads, list)
        assert any("SLEEP" in p for p in sqli_time.payloads)

    def test_passive_template_empty_payloads(self, loader: TemplateLoader):
        """Passive templates have empty payload lists."""
        templates = loader.load_all()
        headers_templates = [t for t in templates if t.id == "security-headers"]
        assert len(headers_templates) == 1

        headers = headers_templates[0]
        assert headers.is_passive
        assert headers.payload_list == []


# ═══════════════════════════════════════════════════════════════════
# Matcher Logic Tests
# ═══════════════════════════════════════════════════════════════════


class TestMatcherBehaviour:
    """Test the structural properties of matchers in loaded templates."""

    @pytest.fixture
    def all_templates(self) -> list[FuzzTemplate]:
        loader = TemplateLoader(templates_dir=TEMPLATES_DIR)
        return loader.load_all()

    def test_all_matcher_types_are_valid(self, all_templates: list[FuzzTemplate]):
        """Every matcher in every template uses a valid type."""
        for t in all_templates:
            for m in t.matchers:
                assert m.type in VALID_MATCHER_TYPES, (
                    f"Template '{t.id}' has matcher with invalid type '{m.type}'"
                )

    def test_all_matcher_parts_are_valid(self, all_templates: list[FuzzTemplate]):
        """Every matcher in every template uses a valid part."""
        for t in all_templates:
            for m in t.matchers:
                assert m.part in VALID_MATCHER_PARTS, (
                    f"Template '{t.id}' has matcher with invalid part '{m.part}'"
                )

    def test_all_matcher_conditions_are_valid(self, all_templates: list[FuzzTemplate]):
        """Every matcher condition is 'or' or 'and'."""
        for t in all_templates:
            assert t.matchers_condition in VALID_CONDITIONS, (
                f"Template '{t.id}' has invalid matchers_condition '{t.matchers_condition}'"
            )
            for m in t.matchers:
                assert m.condition in VALID_CONDITIONS, (
                    f"Template '{t.id}' has matcher with invalid condition '{m.condition}'"
                )

    def test_regex_matchers_compile(self, all_templates: list[FuzzTemplate]):
        """All regex patterns in all templates compile without errors."""
        import re
        for t in all_templates:
            for m in t.matchers:
                if m.type == "regex":
                    for pattern in m.regex:
                        try:
                            re.compile(pattern)
                        except re.error as exc:
                            pytest.fail(
                                f"Template '{t.id}' has invalid regex: "
                                f"'{pattern}' — {exc}"
                            )

    def test_timing_matchers_have_threshold(self, all_templates: list[FuzzTemplate]):
        """All timing matchers have a positive threshold."""
        for t in all_templates:
            for m in t.matchers:
                if m.type == "timing":
                    assert m.threshold_ms > 0, (
                        f"Template '{t.id}' has timing matcher with "
                        f"threshold_ms={m.threshold_ms}"
                    )

    def test_word_matchers_have_words(self, all_templates: list[FuzzTemplate]):
        """All word matchers have at least one word."""
        for t in all_templates:
            for m in t.matchers:
                if m.type == "word":
                    assert len(m.words) > 0, (
                        f"Template '{t.id}' has word matcher with no words"
                    )

    def test_all_tags_lowercase(self, all_templates: list[FuzzTemplate]):
        """All tags across all templates are lowercase."""
        for t in all_templates:
            for tag in t.tags:
                assert tag == tag.lower(), (
                    f"Template '{t.id}' has non-lowercase tag: '{tag}'"
                )


# ═══════════════════════════════════════════════════════════════════
# Specific Template Tests
# ═══════════════════════════════════════════════════════════════════


class TestSpecificTemplates:
    """Test specific properties of individual built-in templates."""

    @pytest.fixture
    def templates(self) -> dict[str, FuzzTemplate]:
        loader = TemplateLoader(templates_dir=TEMPLATES_DIR)
        return {t.id: t for t in loader.load_all()}

    def test_xss_reflected_is_high(self, templates: dict[str, FuzzTemplate]):
        assert templates["xss-reflected"].severity == SeverityLevel.HIGH

    def test_sqli_error_is_critical(self, templates: dict[str, FuzzTemplate]):
        assert templates["sqli-error"].severity == SeverityLevel.CRITICAL

    def test_sqli_time_is_critical(self, templates: dict[str, FuzzTemplate]):
        assert templates["sqli-time"].severity == SeverityLevel.CRITICAL

    def test_sqli_time_has_timing_matcher(self, templates: dict[str, FuzzTemplate]):
        t = templates["sqli-time"]
        timing_matchers = [m for m in t.matchers if m.type == "timing"]
        assert len(timing_matchers) >= 1
        assert timing_matchers[0].threshold_ms > 0

    def test_security_headers_is_passive(self, templates: dict[str, FuzzTemplate]):
        assert templates["security-headers"].is_passive

    def test_sensitive_exposure_is_passive(self, templates: dict[str, FuzzTemplate]):
        assert templates["sensitive-exposure"].is_passive

    def test_open_redirect_is_medium(self, templates: dict[str, FuzzTemplate]):
        assert templates["open-redirect"].severity == SeverityLevel.MEDIUM

    def test_ssrf_basic_is_high(self, templates: dict[str, FuzzTemplate]):
        assert templates["ssrf-basic"].severity == SeverityLevel.HIGH

    def test_ssti_basic_is_critical(self, templates: dict[str, FuzzTemplate]):
        assert templates["ssti-basic"].severity == SeverityLevel.CRITICAL

    def test_path_traversal_is_high(self, templates: dict[str, FuzzTemplate]):
        assert templates["path-traversal"].severity == SeverityLevel.HIGH

    def test_all_expected_ids_present(self, templates: dict[str, FuzzTemplate]):
        """All expected template IDs exist."""
        expected_ids = {
            "xss-reflected",
            "sqli-error",
            "sqli-time",
            "ssrf-basic",
            "ssti-basic",
            "path-traversal",
            "open-redirect",
            "security-headers",
            "sensitive-exposure",
        }
        actual_ids = set(templates.keys())
        missing = expected_ids - actual_ids
        assert not missing, f"Missing template IDs: {missing}"
