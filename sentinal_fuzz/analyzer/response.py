"""Response analyzer for Sentinal-Fuzz.

Provides methods for comparing fuzzed responses against baselines
to detect vulnerabilities. Used by fuzzers after sending payloads
to determine if the target is vulnerable.

Usage::

    from sentinal_fuzz.analyzer.response import ResponseAnalyzer

    analyzer = ResponseAnalyzer()

    if analyzer.error_leak(response.text):
        print("Database error detected!")

    if analyzer.timing_anomaly(baseline_ms=50, fuzzed_ms=5200):
        print("Time-based blind injection detected!")
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sentinal_fuzz.utils.logger import get_logger

log = get_logger("analyzer")


# ── Comprehensive Error Signature Database ────────────────────────
#
# Organized by technology for clear attribution.  Each entry maps a
# human-readable category to a list of regex pattern strings.  The
# compiled patterns below are built from this dict automatically.
#

ERROR_SIGNATURES: dict[str, list[str]] = {
    # ── MySQL ──────────────────────────────────────────────────────
    "mysql": [
        r"You have an error in your SQL syntax",
        r"SQL syntax.*?MySQL",
        r"Warning.*?\Wmysql_",
        r"mysql_fetch_array\(\)",
        r"mysql_fetch_assoc\(\)",
        r"mysql_num_rows\(\)",
        r"mysql_connect\(\)",
        r"MySqlException",
        r"com\.mysql\.jdbc",
        r"MySqlClient\.",
        r"MySQL server version for the right syntax",
        r"Unknown column '\w+' in",
        r"Table '\w+\.\w+' doesn't exist",
    ],

    # ── PostgreSQL ─────────────────────────────────────────────────
    "postgresql": [
        r"PostgreSQL.*?ERROR",
        r"ERROR:\s+unterminated",
        r"ERROR:\s+syntax error at or near",
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"pg_connect\(\)",
        r"PSQLException",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+invalid input syntax for",
        r"current transaction is aborted",
    ],

    # ── Microsoft SQL Server ───────────────────────────────────────
    "mssql": [
        r"Unclosed quotation mark after the character string",
        r"Microsoft SQL Native Client",
        r"Microsoft.*?ODBC.*?SQL Server",
        r"Microsoft OLE DB Provider",
        r"SqlException",
        r"System\.Data\.SqlClient",
        r"Incorrect syntax near",
        r"mssql_query\(\)",
        r"Server Error in '/' Application",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"Conversion failed when converting",
    ],

    # ── Oracle ─────────────────────────────────────────────────────
    "oracle": [
        r"ORA-01756",               # quoted string not properly terminated
        r"ORA-00933",               # SQL command not properly ended
        r"ORA-00936",               # missing expression
        r"ORA-00942",               # table or view does not exist
        r"ORA-01756",               # quoted string not properly terminated
        r"ORA-\d{5}",               # catch-all Oracle error codes
        r"oracle\.jdbc",
        r"OracleException",
        r"Oracle error",
        r"ORA-\d+:\s+",
    ],

    # ── SQLite ─────────────────────────────────────────────────────
    "sqlite": [
        r"SQLite3::query\(\)",
        r"sqlite3\.OperationalError",
        r'near "UNION": syntax error',
        r'near "\w+": syntax error',
        r"SQLITE_ERROR",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"unrecognized token:",
    ],

    # ── Generic SQL ────────────────────────────────────────────────
    "sql_generic": [
        r"SQLSTATE\[",
        r"SQL.*?syntax.*?error",
        r"unexpected end of SQL command",
        r"Dynamic SQL Error",
        r"Syntax error in SQL statement",
        r"supplied argument is not a valid.*?result",
        r"Invalid column name",
        r"Unknown column",
    ],

    # ── PHP Errors ─────────────────────────────────────────────────
    "php": [
        r"Warning:\s+mysql_",
        r"Warning:\s+pg_",
        r"Warning:\s+mysqli_",
        r"Fatal error:\s+",
        r"Parse error:\s+syntax error",
        r"PHP (?:Parse|Fatal|Warning) error",
        r"include\(\).*?failed opening",
        r"Undefined (?:variable|index|offset):\s+",
        r"on line \d+",
    ],

    # ── Python Errors ──────────────────────────────────────────────
    "python": [
        r"Traceback \(most recent call last\)",
        r'File ".*?", line \d+',
        r"SyntaxError:\s+",
        r"IndentationError:\s+",
        r"NameError:\s+name '\w+' is not defined",
        r"TypeError:\s+",
        r"ValueError:\s+",
        r"KeyError:\s+",
        r"django\.core\.exceptions",
        r"flask\.debughelpers",
    ],

    # ── Java / JVM Errors ──────────────────────────────────────────
    "java": [
        r"java\.sql\.SQLException",
        r"java\.lang\.\w+Exception",
        r"javax\.servlet\.ServletException",
        r"OgnlException",
        r"at [\w.$]+\([\w.]+:\d+\)",        # Java stack trace line
        r"org\.apache\.jasper\.JasperException",
        r"org\.hibernate\.exception",
        r"org\.springframework\.\w+Exception",
        r"java\.io\.FileNotFoundException",
        r"java\.lang\.NullPointerException",
    ],

    # ── .NET Errors ────────────────────────────────────────────────
    "dotnet": [
        r"System\.Web\.HttpException",
        r"System\.NullReferenceException",
        r"System\.ArgumentException",
        r"System\.InvalidOperationException",
        r"Server Error in '/' Application",
        r"ASP\.NET is configured to show verbose error messages",
        r"Runtime Error",
        r"[A-Za-z.]+Exception:\s+",
    ],

    # ── Ruby Errors ────────────────────────────────────────────────
    "ruby": [
        r"ActionController::RoutingError",
        r"ActiveRecord::StatementInvalid",
        r"NoMethodError",
        r"RuntimeError",
        r"SyntaxError",
    ],

    # ── Generic Info Leakage ───────────────────────────────────────
    "info_leak": [
        r"(?:stack\s*trace|traceback|backtrace)",
        r"(?:undefined method|undefined variable)",
        r"(?:internal server error)",
        r"(?:debug.*?mode.*?enabled)",
        r"(?:root:|admin:|password\s*=)",
        r"(?:DB_HOST|DB_PASSWORD|DATABASE_URL)\s*=",
    ],
}

# ── Compile patterns for runtime use ──────────────────────────────
# Flat lists used by error_leak() and info_leak() methods.

_DB_ERROR_PATTERNS: list[re.Pattern[str]] = []
for _category, _patterns in ERROR_SIGNATURES.items():
    if _category == "info_leak":
        continue  # Handled separately
    for _pat in _patterns:
        try:
            _DB_ERROR_PATTERNS.append(re.compile(_pat, re.IGNORECASE))
        except re.error:
            pass  # Skip invalid regexes at import time

_INFO_LEAK_PATTERNS: list[re.Pattern[str]] = []
for _pat in ERROR_SIGNATURES.get("info_leak", []):
    try:
        _INFO_LEAK_PATTERNS.append(re.compile(_pat, re.IGNORECASE))
    except re.error:
        pass


@dataclass
class MatchResult:
    """Result of a response analysis match.

    Attributes:
        matched:     Whether the analysis found a match.
        pattern:     The pattern or rule that triggered the match.
        evidence:    The matched text or reason string.
        confidence:  Confidence score (0.0-1.0).
    """

    matched: bool = False
    pattern: str = ""
    evidence: str = ""
    confidence: float = 0.0


@dataclass
class ResponseAnalyzer:
    """Stateless analyzer for comparing HTTP responses.

    Methods analyze a fuzzed response against baselines, error databases,
    and timing heuristics to determine if a vulnerability exists.

    Attributes:
        timing_threshold_ms:  Default threshold for timing anomaly detection.
        body_diff_threshold:  Minimum character difference ratio to flag anomalies.
    """

    timing_threshold_ms: float = 3000.0
    body_diff_threshold: float = 0.3

    def is_vulnerable(
        self,
        baseline_body: str,
        fuzzed_body: str,
        matcher: dict[str, object],
    ) -> MatchResult:
        """Determine if a fuzzed response indicates a vulnerability.

        Applies the matcher rules to compare the baseline and fuzzed
        responses. Supports multiple matcher types:
        - ``"word"``:  Check if specific words appear in the fuzzed response.
        - ``"regex"``: Check if regex patterns match in the fuzzed response.
        - ``"status"``: Check if the response status code matches.
        - ``"diff"``:  Check if the response body differs significantly from baseline.

        Args:
            baseline_body: The normal response body (no payload).
            fuzzed_body:   The response body after injecting a payload.
            matcher:       A dict defining the match rules. Expects keys:
                          ``"type"`` (str), ``"patterns"`` or ``"words"`` (list),
                          ``"condition"`` (str, "or"|"and", default "or").

        Returns:
            A ``MatchResult`` with match status and evidence.
        """
        match_type = str(matcher.get("type", "word"))
        condition = str(matcher.get("condition", "or"))

        if match_type == "word":
            return self._match_words(
                fuzzed_body,
                [str(w) for w in matcher.get("words", [])],
                condition,
            )
        elif match_type == "regex":
            return self._match_regex(
                fuzzed_body,
                [str(p) for p in matcher.get("regex", matcher.get("patterns", []))],
                condition,
            )
        elif match_type == "diff":
            return self._match_diff(baseline_body, fuzzed_body)
        else:
            log.warning("Unknown matcher type: %s", match_type)
            return MatchResult(matched=False)

    def _match_words(
        self, body: str, words: list[str], condition: str
    ) -> MatchResult:
        """Check if specific words appear in the response body."""
        body_lower = body.lower()
        matches = [w for w in words if w.lower() in body_lower]

        matched = len(matches) == len(words) if condition == "and" else len(matches) > 0

        if matched:
            return MatchResult(
                matched=True,
                pattern=f"word:{condition}",
                evidence=f"Matched words: {matches}",
                confidence=min(1.0, len(matches) * 0.5),
            )
        return MatchResult(matched=False)

    def _match_regex(
        self, body: str, patterns: list[str], condition: str
    ) -> MatchResult:
        """Check if regex patterns match in the response body."""
        matches: list[str] = []
        for pattern in patterns:
            try:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    matches.append(match.group(0))
            except re.error as exc:
                log.warning("Invalid regex pattern '%s': %s", pattern, exc)

        matched = len(matches) == len(patterns) if condition == "and" else len(matches) > 0

        if matched:
            return MatchResult(
                matched=True,
                pattern=f"regex:{condition}",
                evidence=f"Matched patterns: {matches[:3]}",  # Cap at 3 for readability
                confidence=min(1.0, len(matches) * 0.4),
            )
        return MatchResult(matched=False)

    def _match_diff(self, baseline: str, fuzzed: str) -> MatchResult:
        """Check if the fuzzed body differs significantly from baseline."""
        if not baseline:
            return MatchResult(matched=False)

        # Simple character-level diff ratio
        max_len = max(len(baseline), len(fuzzed))
        if max_len == 0:
            return MatchResult(matched=False)

        diff_len = abs(len(baseline) - len(fuzzed))
        diff_ratio = diff_len / max_len

        if diff_ratio > self.body_diff_threshold:
            return MatchResult(
                matched=True,
                pattern="body_diff",
                evidence=(
                    f"Body length diff: {diff_ratio:.1%}"
                    f" (baseline={len(baseline)}, fuzzed={len(fuzzed)})"
                ),
                confidence=min(1.0, diff_ratio),
            )
        return MatchResult(matched=False)

    def timing_anomaly(
        self,
        baseline_ms: float,
        fuzzed_ms: float,
        threshold_ms: float | None = None,
    ) -> MatchResult:
        """Detect time-based blind injection via response timing anomaly.

        Compares the fuzzed response time against the baseline. If the
        fuzzed request took significantly longer (above threshold), this
        may indicate a time-based blind SQL injection or command injection.

        Args:
            baseline_ms:   Baseline response time in milliseconds.
            fuzzed_ms:     Fuzzed response time in milliseconds.
            threshold_ms:  Minimum delay to consider anomalous (default: 3000ms).

        Returns:
            A ``MatchResult`` indicating whether a timing anomaly was detected.
        """
        thresh = threshold_ms or self.timing_threshold_ms
        delta = fuzzed_ms - baseline_ms

        if delta >= thresh:
            confidence = min(1.0, delta / (thresh * 2))
            log.info(
                "Timing anomaly: baseline=%.0fms, fuzzed=%.0fms, delta=%.0fms",
                baseline_ms, fuzzed_ms, delta,
            )
            return MatchResult(
                matched=True,
                pattern="timing",
                evidence=(
                    f"Response delay: {delta:.0f}ms"
                    f" (baseline: {baseline_ms:.0f}ms, threshold: {thresh:.0f}ms)"
                ),
                confidence=confidence,
            )
        return MatchResult(matched=False)

    def error_leak(self, response_body: str) -> MatchResult:
        """Detect database error messages or stack traces in the response.

        Scans the response body for known database error patterns that
        indicate SQL injection or other injection vulnerabilities.

        Args:
            response_body: The HTTP response body text.

        Returns:
            A ``MatchResult`` indicating whether error leakage was detected.
        """
        for pattern in _DB_ERROR_PATTERNS:
            match = pattern.search(response_body)
            if match:
                log.info("DB error leak detected: %s", match.group(0)[:80])
                return MatchResult(
                    matched=True,
                    pattern=f"db_error:{pattern.pattern}",
                    evidence=match.group(0)[:200],
                    confidence=0.9,
                )

        return MatchResult(matched=False)

    def info_leak(self, response_body: str) -> MatchResult:
        """Detect sensitive information disclosure in the response.

        Scans for stack traces, debug output, framework error pages,
        and other information leakage patterns.

        Args:
            response_body: The HTTP response body text.

        Returns:
            A ``MatchResult`` indicating whether info leakage was detected.
        """
        for pattern in _INFO_LEAK_PATTERNS:
            match = pattern.search(response_body)
            if match:
                return MatchResult(
                    matched=True,
                    pattern=f"info_leak:{pattern.pattern}",
                    evidence=match.group(0)[:200],
                    confidence=0.6,
                )

        return MatchResult(matched=False)

    def reflection_check(self, payload: str, response_body: str) -> MatchResult:
        """Check if an injected payload is reflected in the response.

        Used primarily for reflected XSS detection. Checks whether the
        exact payload string appears in the response body without
        encoding or sanitization.

        Args:
            payload:       The injected payload string.
            response_body: The HTTP response body text.

        Returns:
            A ``MatchResult`` indicating whether the payload was reflected.
        """
        if payload in response_body:
            return MatchResult(
                matched=True,
                pattern="reflection",
                evidence=f"Payload reflected verbatim: {payload[:100]}",
                confidence=0.85,
            )
        return MatchResult(matched=False)
