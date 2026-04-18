# Sentinal-Fuzz — Detection Signatures Reference

> **Purpose**: This document defines the exact response patterns (regex, status codes, timing thresholds, header patterns) that the Sentinal-Fuzz template engine uses to identify vulnerabilities. Each section corresponds to a vulnerability class and provides copy-paste-ready patterns for the template system.

---

## Table of Contents

1. [Reflected XSS](#1-reflected-xss)
2. [Stored XSS](#2-stored-xss)
3. [DOM XSS](#3-dom-xss)
4. [SQL Injection — Error-Based](#4-sql-injection--error-based)
5. [SQL Injection — Time-Based Blind](#5-sql-injection--time-based-blind)
6. [SQL Injection — Boolean-Based Blind](#6-sql-injection--boolean-based-blind)
7. [SSRF](#7-ssrf)
8. [SSTI](#8-ssti)
9. [Path Traversal / LFI](#9-path-traversal--lfi)
10. [Open Redirect](#10-open-redirect)
11. [Command Injection](#11-command-injection)
12. [XXE](#12-xxe)
13. [CORS Misconfiguration](#13-cors-misconfiguration)
14. [Sensitive Data Exposure](#14-sensitive-data-exposure)
15. [Security Headers Missing](#15-security-headers-missing)
16. [Default Credentials](#16-default-credentials)
17. [Exposed Admin Panels](#17-exposed-admin-panels)
18. [Directory Listing](#18-directory-listing)

---

## 1. Reflected XSS

### Response Body Patterns (word match)
The primary detection method is **exact string matching** — check if the injected payload appears unencoded in the response body.

```
Type: word (exact match)
Part: body
Condition: or

Match strings (correspond to payloads used):
- <script>alert('XSS')</script>
- <script>alert(1)</script>
- <img src=x onerror=alert(1)>
- <svg/onload=alert(1)>
- <svg onload=alert(1)>
- <body onload=alert(1)>
- <details open ontoggle=alert(1)>
- javascript:alert(1)
```

### HTTP Status Codes
```
Match: 200, 201, 301, 302, 303
```

### Header Patterns (positive match required)
```
Content-Type: text/html
```

### Header Patterns (negative — vuln diminished if present)
```
Content-Security-Policy: .*script-src(?!.*'unsafe-inline')
```

### Notes
- If the payload is HTML-entity-encoded (e.g., `&lt;script&gt;`), it is NOT a valid XSS → do not flag.
- `Content-Type: application/json` or `text/plain` responses should be excluded.

---

## 2. Stored XSS

### Response Body Patterns (word match)
```
Type: word (exact match)
Part: body
Condition: or

Match strings (unique marker format):
- <script>alert('SFFUZZ-{ID}')</script>
- <img src=x onerror=alert('SFFUZZ-{ID}')>
- <svg/onload=alert('SFFUZZ-{ID}')>
```

### Detection Logic
- The marker must be found on a **different page** than the one it was submitted to.
- The marker must appear unencoded.
- The response `Content-Type` must be `text/html`.

### HTTP Status Codes
```
Match: 200
```

---

## 3. DOM XSS

### Static Analysis — Source Patterns (JavaScript)
```regex
# DOM Sources — regex patterns to find in JS files
(?:document\.URL|document\.documentURI|document\.baseURI)
(?:location\.href|location\.hash|location\.search|location\.pathname)
(?:document\.referrer)
(?:window\.name)
(?:document\.cookie)
(?:window\.postMessage|addEventListener\s*\(\s*['"]message['"])
```

### Static Analysis — Sink Patterns (JavaScript)
```regex
# DOM Sinks — regex patterns to find in JS files
(?:\.innerHTML\s*=|\.outerHTML\s*=)
(?:document\.write\s*\(|document\.writeln\s*\()
(?:eval\s*\()
(?:setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`])
(?:new\s+Function\s*\()
(?:\.href\s*=)
(?:\.src\s*=)
(?:jQuery\s*\(\s*['"`]<|jQuery\.html\s*\(|\$\s*\(\s*['"`]<|\$\.html\s*\()
```

### Notes
- Static findings are heuristic — report as "Potential DOM XSS" with source–sink pair identified.
- Dynamic confirmation (headless browser) promotes to "Confirmed."

---

## 4. SQL Injection — Error-Based

### Response Body Patterns (regex)
```regex
# MySQL
SQL syntax.*?MySQL
Warning.*?\bmysql_
MySqlException
MySqlClient\.
com\.mysql\.jdbc

# PostgreSQL
PostgreSQL.*?ERROR
pg_query\(\)
pg_exec\(\)
unterminated quoted string at or near
PSQLException
org\.postgresql\.util

# Microsoft SQL Server
Microsoft.*?ODBC.*?SQL Server
Unclosed quotation mark after the character string
Microsoft OLE DB Provider for SQL Server
\bOLE DB\b.*?\bSQL Server\b
SqlException.*?System\.Data\.SqlClient
Incorrect syntax near

# Oracle
ORA-\d{5}
oracle\.jdbc
PLS-\d{4,5}

# SQLite
SQLite3::|SQLITE_ERROR
sqlite3\.OperationalError
unrecognized token

# Generic
SQLSTATE\[
syntax error at or near
SQL command not properly ended
Syntax error in string in query expression
near ".*?": syntax error
```

### HTTP Status Codes
```
Match: 200, 500 (errors often returned with either)
```

### Extractor Pattern (for evidence capture)
```regex
(?i)(sql syntax|mysql_fetch|ORA-\d+|pg_query|ODBC SQL Server|SQLSTATE\[|sqlite3|PostgreSQL.*ERROR|Unclosed quotation|SqlException)
```

---

## 5. SQL Injection — Time-Based Blind

### Response Time Threshold
```yaml
baseline_samples: 3               # requests to establish baseline
injected_delay_seconds: 5          # delay we inject
tolerance_seconds: 1               # account for network jitter
confirmation_delay_seconds: 3      # second probe with different delay

# Detection formula:
# IF response_time >= (baseline_avg + injected_delay - tolerance)
#    THEN potential time-based SQLi
# CONFIRM: repeat with confirmation_delay_seconds
# IF response_time ≈ (baseline_avg + confirmation_delay)
#    THEN confirmed time-based SQLi
```

### Response Body Patterns
```
None — the response body is typically identical to baseline.
The only signal is the response time delta.
```

### HTTP Status Codes
```
Match: 200 (usually unchanged)
```

---

## 6. SQL Injection — Boolean-Based Blind

### Response Comparison Logic
```yaml
# Step 1: Capture baseline
baseline_response_length: <measured>
baseline_status_code: <measured>
baseline_body_hash: <measured>  # hash after stripping dynamic content (CSRF tokens, timestamps)

# Step 2: Compare TRUE payload response
true_response_length_delta_threshold: 10%  # within 10% of baseline = match
true_status_code: must match baseline

# Step 3: Compare FALSE payload response
false_response_length_delta_threshold: 10%  # must differ by >10% from baseline
false_status_code: may differ from baseline

# Confirmation:
# TRUE ≈ baseline AND FALSE ≠ baseline → boolean-based blind SQLi
```

### Dynamic Content Stripping (apply before comparison)
```regex
# Remove these patterns before comparing body hashes:
csrf[_-]?token["']\s*[:=]\s*["'][a-zA-Z0-9+/=]+["']
name=["']_token["']\s+value=["'][^"']+["']
\d{10,13}                    # Unix timestamps
\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}   # ISO timestamps
nonce=["'][a-fA-F0-9]+["']
```

---

## 7. SSRF

### Response Body Patterns — Cloud Metadata
```regex
# AWS metadata
ami-id
instance-id
iam/security-credentials
AccessKeyId
SecretAccessKey

# GCP metadata
computeMetadata
project/project-id

# DigitalOcean metadata
droplet_id

# Azure metadata
azuremonitor
```

### Response Body Patterns — Internal Services
```regex
# Common internal service responses
<title>(?:Dashboard|Apache Tomcat|Welcome to nginx|IIS Windows Server)</title>
phpinfo\(\)
Server at .*? Port \d+
```

### Response Body Patterns — Error Leakage
```regex
# Errors revealing internal resolution
Connection refused.*?127\.0\.0\.1
couldn't connect to host
getaddrinfo.*?failed
Name or service not known
No route to host
Connection timed out.*?(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)
```

### OOB Detection
```yaml
# If using a callback server
callback_path: /ssrf-{SCAN_ID}
match: HTTP request received at callback server from target IP
```

### HTTP Status Codes
```
Match: 200 (with internal content), 500 (error leakage)
```

---

## 8. SSTI

### Response Body Patterns — Computation Results
```regex
# Arithmetic probe results
# For {{7*7}} → look for 49 (but exclude natural occurrences)
# Use unique multiplications to reduce false positives:

# {{7*191}} → 1337
\b1337\b

# {{123*456}} → 56088
\b56088\b

# {{7*7}} → 49 (generic, use as fallback)
\b49\b

# {{7*'7'}} → 7777777 (Jinja2-specific string multiplication)
7777777
```

### Response Body Patterns — Template Engine Errors
```regex
# Jinja2 (Python)
jinja2\.exceptions
UndefinedError
TemplateSyntaxError.*?jinja

# Twig (PHP)
Twig_Error_Syntax
Twig\\Error\\SyntaxError

# Freemarker (Java)
FreeMarkerException|freemarker\.core\.|freemarker\.template\.

# Velocity (Java)
org\.apache\.velocity
VelocityException

# Pebble (Java)
com\.mitchellbosecke\.pebble
PebbleException

# Thymeleaf (Java)
org\.thymeleaf\.exceptions
TemplateProcessingException

# ERB (Ruby)
SyntaxError.*?erb
```

### HTTP Status Codes
```
Match: 200 (computation result in body), 500 (template engine error)
```

---

## 9. Path Traversal / LFI

### Response Body Patterns — Linux
```regex
# /etc/passwd
root:x:0:0:
root:.*?:0:0:
daemon:.*?:1:1:
bin:.*?:2:2:
nobody:.*?:\d+:\d+:

# /etc/shadow (if readable)
root:\$[0-9a-zA-Z\$\.\/]+:

# /etc/hosts
127\.0\.0\.1\s+localhost

# /proc/self/environ
HOSTNAME=|PATH=|HOME=
```

### Response Body Patterns — Windows
```regex
# win.ini
\[fonts\]
\[extensions\]
\[mci extensions\]
\[files\]

# boot.ini
\[boot loader\]
\[operating systems\]
multi\(0\)disk\(0\)

# Windows system info
\[Microsoft\]|\[Windows\]
```

### HTTP Status Codes
```
Match: 200
```

### Response Size
```yaml
# A successful LFI typically returns more content than an error
min_response_length: 50  # /etc/passwd is always > 50 bytes
```

---

## 10. Open Redirect

### Response Header Patterns
```regex
# Location header pointing to attacker domain
# (after injecting https://evil.com as payload)
Location:\s*https?://evil\.com
Location:\s*//evil\.com
Location:\s*https?://.*?evil\.com

# Null byte bypass
Location:.*?%00

# Protocol-relative
Location:\s*//[^/]
```

### Response Body Patterns (meta-refresh / JS redirect)
```regex
# Meta refresh redirect
<meta\s+http-equiv=["']refresh["']\s+content=["']\d+;\s*url=https?://evil\.com

# JavaScript redirect
window\.location\s*=\s*["']https?://evil\.com
document\.location\s*=\s*["']https?://evil\.com
location\.href\s*=\s*["']https?://evil\.com
location\.replace\s*\(\s*["']https?://evil\.com
```

### HTTP Status Codes
```
Match: 301, 302, 303, 307, 308
```

---

## 11. Command Injection

### Response Body Patterns — Command Output
```regex
# Linux 'id' command output
uid=\d+\(\w+\)\s+gid=\d+\(\w+\)
uid=0\(root\)

# Linux 'whoami' output (if username is known)
# Difficult to pattern-match generically

# Linux 'cat /etc/passwd'
root:x:0:0:

# Windows 'whoami'
nt authority\\
[a-zA-Z]+\\[a-zA-Z]+

# Windows 'ipconfig'
Windows IP Configuration
IPv4 Address
Subnet Mask
Default Gateway
```

### Response Time Threshold (blind command injection)
```yaml
# Same logic as time-based SQLi
baseline_samples: 3
injected_delay_seconds: 5          # via: ; sleep 5
tolerance_seconds: 1
confirmation_delay_seconds: 3      # via: ; sleep 3
```

### HTTP Status Codes
```
Match: 200, 500
```

---

## 12. XXE

### Response Body Patterns — File Content
```regex
# /etc/passwd content (same as LFI)
root:x:0:0:
root:.*?:0:0:

# win.ini content
\[fonts\]
\[extensions\]
```

### Response Body Patterns — XML Parser Errors
```regex
# Java XML parsers
SAXParseException
javax\.xml\.parsers
org\.xml\.sax

# Python XML parsers
lxml\.etree
xml\.parsers\.expat
XMLSyntaxError
ExpatError

# PHP XML parsers
DOMDocument::load
simplexml_load_string
XMLReader::

# .NET XML parsers
System\.Xml
XmlException

# Generic
XML parsing error
not well-formed
entity.*?not defined
```

### OOB Detection
```yaml
callback_path: /xxe-{SCAN_ID}
match: HTTP request received at callback server from target IP
# DTD payload triggers external entity fetch to our server
```

### HTTP Status Codes
```
Match: 200 (file content returned), 400, 500 (parser errors)
```

---

## 13. CORS Misconfiguration

### Response Header Patterns
```yaml
# Critical: Origin reflection with credentials
- header: Access-Control-Allow-Origin
  match_value: "https://evil.com"  # exact match with our injected origin
  severity: high

- header: Access-Control-Allow-Credentials
  match_value: "true"
  severity_modifier: +critical  # combined with reflected origin = critical

# Risky: Wildcard origin
- header: Access-Control-Allow-Origin
  match_value: "*"
  severity: medium

# Risky: Null origin allowed
- header: Access-Control-Allow-Origin
  match_value: "null"
  severity: high

# Subdomain bypass
- header: Access-Control-Allow-Origin
  match_regex: "https?://.*evil\\.com"
  severity: high
```

### HTTP Status Codes
```
Match: 200 (preflight: 204)
```

---

## 14. Sensitive Data Exposure

### Response Body Patterns — API Keys & Secrets
```regex
# AWS Access Key
AKIA[0-9A-Z]{16}

# AWS Secret Key (in same response)
(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?

# Google API Key
AIza[0-9A-Za-z\-_]{35}

# GitHub Personal Access Token
ghp_[0-9A-Za-z]{36}

# GitHub OAuth Token
gho_[0-9A-Za-z]{36}

# Stripe Secret Key
sk_live_[0-9a-zA-Z]{24,}

# Stripe Publishable Key (lower severity)
pk_live_[0-9a-zA-Z]{24,}

# Slack Token
xox[bpors]-[0-9a-zA-Z]{10,48}

# Heroku API Key
[hH]eroku.*?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}

# Generic API key patterns
(?:api[_-]?key|apikey|api_secret|access_token|auth_token|client_secret)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}['"]?

# Private Key
-----BEGIN\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s)?PRIVATE\sKEY-----

# JWT Token (may be expected — lower severity)
eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+
```

### Response Body Patterns — Stack Traces & Debug Info
```regex
# Python
Traceback \(most recent call last\)
File ".*?", line \d+
raise\s+\w+Error

# Java
at\s+[\w\.$]+\([\w]+\.java:\d+\)
java\.lang\.\w+Exception
Exception in thread "

# PHP
Fatal error:.*?on line \d+
Stack trace:.*?#\d+
Warning:.*?on line \d+

# .NET / C#
System\.\w+Exception
at\s+[\w.]+\sin\s.*?:line\s\d+
Server Error in '/' Application

# Node.js
at\s+[\w.]+\s\(.*?:\d+:\d+\)
Error:.*?\n\s+at\s+

# Ruby
\.rb:\d+:in\s`
ActionController::RoutingError

# Debug mode indicators
(?:DEBUG|DEVELOPMENT)\s*(?:MODE|=\s*true|=\s*True|=\s*1)
X-Debug-Token
```

### Response Body Patterns — Internal IPs & Infrastructure
```regex
# RFC 1918 Private IPs
(?:^|[^0-9])10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:[^0-9]|$)
(?:^|[^0-9])192\.168\.\d{1,3}\.\d{1,3}(?:[^0-9]|$)
(?:^|[^0-9])172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?:[^0-9]|$)

# Database connection strings
(?:jdbc|mysql|postgresql|mongodb|redis|amqp):\/\/[^\s<>"']+
Server=.*?;Database=.*?;(?:User\sId|Uid)=
DSN=.*?;(?:PWD|Password)=

# Internal hostnames
(?:internal|staging|dev|test|local)\.[a-zA-Z0-9-]+\.(?:com|net|org|internal|local)
```

### Response Header Patterns
```regex
# Server version disclosure
Server:\s*(?:Apache|nginx|IIS|Tomcat|Jetty)/[\d.]+
X-Powered-By:\s*.+
X-AspNet-Version:\s*.+
X-AspNetMvc-Version:\s*.+
```

---

## 15. Security Headers Missing

### Expected Headers Checklist
```yaml
headers:
  - name: Content-Security-Policy
    required: true
    severity_if_missing: medium
    weak_patterns:
      - "unsafe-inline"          # weakens CSP
      - "unsafe-eval"            # weakens CSP
      - "*"                      # overly permissive source
    severity_if_weak: low

  - name: Strict-Transport-Security
    required: true
    severity_if_missing: medium
    validation:
      - regex: "max-age=(\\d+)"
        min_value: 31536000       # at least 1 year
      - should_include: "includeSubDomains"
    severity_if_weak: low

  - name: X-Frame-Options
    required: true
    severity_if_missing: medium
    valid_values:
      - "DENY"
      - "SAMEORIGIN"
    severity_if_invalid: medium

  - name: X-Content-Type-Options
    required: true
    severity_if_missing: low
    valid_values:
      - "nosniff"

  - name: Referrer-Policy
    required: true
    severity_if_missing: low
    valid_values:
      - "no-referrer"
      - "no-referrer-when-downgrade"
      - "origin"
      - "origin-when-cross-origin"
      - "same-origin"
      - "strict-origin"
      - "strict-origin-when-cross-origin"

  - name: Permissions-Policy
    required: false
    severity_if_missing: info
    description: "Controls browser feature access (camera, mic, geolocation)"

  - name: X-XSS-Protection
    required: false    # deprecated in modern browsers
    severity_if_missing: info
    valid_values:
      - "1; mode=block"

  - name: Cache-Control
    required: conditional   # only for authenticated/sensitive pages
    severity_if_missing: low
    valid_values:
      - "no-store"
      - "no-cache, no-store, must-revalidate"
```

---

## 16. Default Credentials

### Login Success Detection
```yaml
# Positive indicators (login succeeded)
positive_body_patterns:
  - regex: "(?i)(dashboard|welcome|logout|sign.?out|my.?account|admin.?panel)"
  - regex: "(?i)(successfully logged in|login successful|authenticated)"

positive_header_patterns:
  - header: Set-Cookie
    regex: "(?i)(session|sid|token|auth|jwt|PHPSESSID|JSESSIONID|connect\\.sid)="

positive_redirect_patterns:
  - header: Location
    regex: "(?i)(/dashboard|/admin|/home|/panel|/console|/manage)"

# Negative indicators (login failed)
negative_body_patterns:
  - regex: "(?i)(invalid|incorrect|wrong|failed|error|denied|unauthorized)"
  - regex: "(?i)(bad credentials|authentication failed|login failed)"
  - regex: "(?i)(try again|account locked|too many attempts)"
```

### Default Credential Pairs
```yaml
credentials:
  # Generic
  - username: admin
    password: admin
  - username: admin
    password: password
  - username: admin
    password: 123456
  - username: admin
    password: admin123
  - username: admin
    password: changeme
  - username: root
    password: root
  - username: root
    password: toor
  - username: root
    password: password
  - username: administrator
    password: administrator
  - username: test
    password: test
  - username: user
    password: user
  - username: guest
    password: guest

  # Product-specific
  - username: tomcat
    password: tomcat
  - username: manager
    password: manager
  - username: admin
    password: tomcat
  - username: admin
    password: manager
```

---

## 17. Exposed Admin Panels

### Path List
```yaml
paths:
  # Generic admin
  - /admin
  - /admin/
  - /admin/login
  - /administrator
  - /administrator/login
  - /login
  - /manage
  - /management

  # WordPress
  - /wp-admin
  - /wp-admin/
  - /wp-login.php

  # PHP apps
  - /phpmyadmin
  - /phpmyadmin/
  - /pma
  - /myadmin

  # Java / Tomcat
  - /manager/html
  - /manager/status
  - /host-manager/html

  # DevOps / Monitoring
  - /jenkins
  - /jenkins/login
  - /grafana
  - /grafana/login
  - /kibana
  - /kibana/app
  - /prometheus
  - /prometheus/graph
  - /solr
  - /solr/admin

  # APIs / Debug
  - /swagger-ui.html
  - /swagger-ui/
  - /api-docs
  - /api-docs/
  - /actuator
  - /actuator/env
  - /actuator/health
  - /console
  - /_debug
  - /debug
  - /elmah.axd
  - /trace.axd

  # cPanel / Webmail
  - /cpanel
  - /webmail
  - /whm
```

### Response Body Patterns — Panel Identification
```regex
# WordPress
wp-login\.php|WordPress|wp-admin

# phpMyAdmin
phpMyAdmin|phpmyadmin|PMA_

# Tomcat Manager
Apache Tomcat|Tomcat Manager|manager-gui

# Jenkins
Jenkins|jenkins-login|j_acegi_security_check

# Grafana
Grafana|grafana-app

# Kibana
kibana-app|Kibana

# Spring Boot Actuator
\{.*?"status"\s*:\s*"UP".*?\}

# Swagger UI
Swagger UI|swagger-ui

# Generic admin patterns
(?i)<title>.*?(?:admin|login|dashboard|control panel|management).*?</title>
(?i)(?:sign\s*in|log\s*in|username|password)\s*(?:<|:)
```

### HTTP Status Codes
```yaml
confirmed_exists: [200]
likely_exists: [401, 403]       # auth required but panel is there
not_found: [404]
```

### False 404 Detection
```yaml
# Compare response with a known-bad path to detect custom 404 pages
control_path: "/sf-definitely-not-a-real-page-82731"
# If the admin path response body ≈ control path response body → it's a custom 404, not a real panel
similarity_threshold: 0.9  # >90% similar = false positive
```

---

## 18. Directory Listing

### Response Body Patterns
```regex
# Apache
<title>Index of /
<h1>Index of /
<pre><img.*?alt="\[.*?\]"

# Nginx
<title>Index of /
<html>\s*<head>\s*<title>Index of

# IIS
<pre><A HREF="/">.*?\[To Parent Directory\]
<H1>.*?- /.*?</H1>

# Generic directory listing indicators
Parent Directory
Last modified
<a href="[^"]+/">[^<]+/</a>
\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2}
<td.*?>\d+(\.\d+)?[KMG]?</td>
```

### HTTP Status Codes
```
Match: 200
```

### Verification
```yaml
# Confirm it's a real directory listing, not a normal page:
# 1. Contains at least 2 file/directory hyperlinks
min_links: 2
link_pattern: '<a href="[^"]+">.*?</a>'

# 2. Contains "Parent Directory" or equivalent
parent_dir_patterns:
  - "Parent Directory"
  - "[To Parent Directory]"
  - '<a href="../">'
```

---

## Quick Reference — Pattern Categories

| Category | Used By | Description |
|----------|---------|-------------|
| `word` | XSS, Stored XSS | Exact string match in response body |
| `regex` | SQLi, LFI, SSTI, XXE, Sensitive Data | Regular expression match in response body |
| `status` | All | HTTP status code matching |
| `header` | CORS, Open Redirect, Security Headers | Response header value matching |
| `time` | Time-based SQLi, Blind CMDi | Response time comparison against baseline |
| `diff` | Boolean SQLi | Response body length/hash comparison |
| `oob` | SSRF, XXE, CMDi | Out-of-band callback server hit |

---

## Implementation Notes

1. **All regex patterns should be compiled with `re.IGNORECASE` by default** unless case sensitivity is critical for the match.
2. **Response body matching should operate on decoded content** — decompress gzip/brotli, decode chunked transfer encoding before matching.
3. **Time-based checks must account for cold starts** — the first request to a dormant application may be slow regardless of injection. Always use baseline averaging.
4. **OOB checks require a callback infrastructure** — this is a Phase 2 feature. For Phase 1, rely on response-based detection only.
5. **Extractors should capture evidence** — when a pattern matches, capture the surrounding ±100 characters for the report. This helps human reviewers confirm findings.
