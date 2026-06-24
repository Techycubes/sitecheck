# sitecheck — implementation walkthrough

A self-guided build order for the stubbed logic. Each step lists **what to
build**, **ordered hint steps** (conceptual, no code), **concepts/gotchas**,
**docs to read**, and **how to verify**. Write the code yourself — the links
are where the *how* lives.

## Before you start
- Activate the venv and install pytest (the one dev-only dependency):
  - PowerShell: `venv\Scripts\Activate.ps1` then `pip install pytest`
- Keep a fast feedback loop open: `pytest` for report work, and
  `python -m sitecheck.cli testphp.vulnweb.com --checks <name>` for live checks.
- Golden rule for every check: a *finding* (missing header, expiring cert,
  exposed file) is normal return data, never an exception. Only raise/record
  `error` on genuine operational failures (host unreachable, DNS timeout).
- Keep every return value JSON-serializable (str/int/list/dict/bool/None) so
  `report.save_report` can dump it straight to JSON.

---

## Order at a glance (easiest → hardest)
1. `report.build_report` — pure logic, tests already written
2. `checks/headers.py` — one GET, dict compare
3. `checks/exposed_files.py` — loop of HEAD requests
4. `checks/security_txt.py` — GET + line parsing
5. `checks/dns_records.py` — dnspython, exception handling
6. `checks/tls.py` — raw ssl/socket, cert parsing
7. `report.save_report` — render markdown/json to disk

Rule of thumb: **pure-logic before network, `requests` before `dnspython`/`ssl`.**

---

## 1. `sitecheck/report.py` → `build_report` (START HERE)
**What:** turn the raw per-check results dict into a severity-ranked
`findings` list + `counts`. No network. Your tests in
`tests/test_report.py` are the target.

**Hint steps:**
1. Read `tests/test_report.py` carefully — it defines the exact input shape
   and the two assertions you must satisfy (a missing header → a finding whose
   text contains "content-security-policy"; an exposed `/.env` → a finding with
   `severity == "high"`).
2. Decide a severity map per check (suggested: exposed_files→high,
   tls invalid/expired→high, expiring→medium, missing header→medium,
   missing SPF/DMARC→medium/low, no security.txt→low).
3. Walk each check's result with `.get()` (never index — a check may have
   returned `{"error": ...}`), and translate it into zero or more finding
   dicts of shape `{severity, check, title, detail}`.
4. Sort `findings` by severity using `SEVERITY_ORDER.index` as the key.
5. Tally `counts` per severity. Return `{domain, findings, counts}`.
6. Run `pytest` until both tests pass.

**Concepts/gotchas:** defensive dict access; a stable sort keyed by a fixed
order tuple; separating "data" from "presentation" (this function returns
data; step 7 renders it).

**Docs:** Python data model & `list.sort(key=...)`
https://docs.python.org/3/howto/sorting.html · pytest basics
https://docs.pytest.org/en/stable/how-to/usage.html

**Verify:** `pytest -q` → both tests green.

---

## 2. `sitecheck/checks/headers.py` → `check_headers`
**What:** GET the site, compare response headers against the
`SECURITY_HEADERS` tuple, return present/missing.

**Hint steps:**
1. Build the URL as `https://{domain}`.
2. Send a GET with `headers={"User-Agent": user_agent}` and a `timeout`
   (~10s). Decide whether to keep `requests`' default redirect-following and
   whether to record the final URL.
3. `response.headers` is case-insensitive — iterate `SECURITY_HEADERS`,
   building a `present` map (name→value) and a `missing` list.
4. Return `{url, status_code, present, missing, error}`.
5. Wrap network errors: either set `error` and return, or let them propagate
   for the CLI to catch (the CLI already handles both).

**Concepts/gotchas:** `requests.exceptions.RequestException` is the catch-all;
always pass a timeout (no default exists); `CaseInsensitiveDict`.

**Docs:** requests quickstart (response headers)
https://requests.readthedocs.io/en/latest/user/quickstart/#response-headers ·
timeouts https://requests.readthedocs.io/en/latest/user/quickstart/#timeouts ·
what each header does (MDN) — Strict-Transport-Security, Content-Security-Policy,
X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy:
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers · OWASP Secure
Headers https://owasp.org/www-project-secure-headers/

**Verify:** `python -m sitecheck.cli github.com --checks headers` then read the
printed report path; github.com sets most headers, a bare test site won't.

---

## 3. `sitecheck/checks/exposed_files.py` → `check_exposed_files`
**What:** HEAD each path in the fixed `SENSITIVE_PATHS` list, flag 200s.

**Hint steps:**
1. Loop `SENSITIVE_PATHS`, building `https://{domain}{path}`.
2. Send a HEAD (cheaper than GET) with the user_agent and a timeout. Pass
   `allow_redirects=False` so a 301/302 to a login/homepage isn't mistaken for
   an exposure — you want the path's own status.
3. Treat a 200 as exposed → append `{path, status_code}` to `exposed`.
4. Catch per-request errors so one bad path doesn't abort the loop; record and
   continue.
5. Return `{base_url, exposed, checked, error}`.

**Concepts/gotchas:** HEAD has no body, so you can't detect soft-404s — note
that limitation; keep the list fixed (this is not a directory buster); the
ethics line is "report, never download or exploit."

**Docs:** requests HEAD & redirects
https://requests.readthedocs.io/en/latest/user/quickstart/#make-a-request ·
redirect handling
https://requests.readthedocs.io/en/latest/user/advanced/#redirection-and-history

**Verify:** `python -m sitecheck.cli testphp.vulnweb.com --checks exposed_files`
(an intentionally vulnerable practice target).

---

## 4. `sitecheck/checks/security_txt.py` → `check_security_txt`
**What:** GET `/.well-known/security.txt` (RFC 9116), parse `Contact:` lines.

**Hint steps:**
1. GET `https://{domain}{WELL_KNOWN_PATH}` with user_agent + timeout. On 404,
   optionally fall back to `LEGACY_PATH`.
2. Only a 200 with a text body counts as `present: True`.
3. Parse the body line by line: split on `:` into `Field: value`; skip `#`
   comments and blank lines; field names are case-insensitive. Collect every
   `Contact` value (order matters per the RFC) into `contacts`.
4. (Optional) capture `Expires`, `Policy`, `Encryption` into a `fields` dict.
5. Return `{url, present, contacts, fields, error}`.
6. **Never** contact the addresses you parse — drafting a disclosure note is a
   later, manual, write-to-`outbox/` step, never automated here.

**Concepts/gotchas:** `str.splitlines()`, `str.partition(":")`, `.strip()`,
`.lower()` for case-insensitive field names.

**Docs:** RFC 9116 (the spec, esp. the Contact field)
https://www.rfc-editor.org/rfc/rfc9116 · securitytxt.org examples
https://securitytxt.org/

**Verify:** `python -m sitecheck.cli google.com --checks security_txt`
(google.com publishes one).

---

## 5. `sitecheck/checks/dns_records.py` → `check_dns`
**What:** look up SPF (TXT on apex) and DMARC (TXT on `_dmarc.<domain>`).

**Hint steps:**
1. Resolve TXT on the apex domain; join each record's chunks and decode, then
   find the one starting `v=spf1`.
2. Resolve TXT on `_dmarc.{domain}`; find the one starting `v=DMARC1`.
3. Map exceptions correctly: `NXDOMAIN` / `NoAnswer` mean "not configured" →
   `present: False` (NOT an error). `NoNameservers` / `Timeout` are real
   errors → populate `error`.
4. Return `{domain, spf:{present,record}, dmarc:{present,record}, error}`.

**Concepts/gotchas:** TXT records arrive as byte-string chunks
(`rdata.strings`) — join then decode; an SPF record is just a specially-shaped
TXT record (there is no dedicated SPF type); distinguishing "missing" from
"lookup failed" is the whole point of this check.

**Docs:** dnspython resolver
https://dnspython.readthedocs.io/en/stable/resolver-class.html · resolver
exceptions https://dnspython.readthedocs.io/en/stable/exceptions.html · DMARC
overview https://dmarc.org/overview/ · SPF
https://www.rfc-editor.org/rfc/rfc7208

**Verify:** `python -m sitecheck.cli google.com --checks dns` (has both); try a
domain you control to see a "missing" result.

---

## 6. `sitecheck/checks/tls.py` → `check_tls` (hardest)
**What:** open a TLS socket, report cert validity, days-to-expiry, protocol.

**Hint steps:**
1. Create a context with `ssl.create_default_context()` (verifies chain +
   hostname for you).
2. Open a TCP socket to `(domain, HTTPS_PORT)` with a timeout, then wrap it
   with `context.wrap_socket(sock, server_hostname=domain)`. Use `with` blocks
   so sockets always close.
3. From the wrapped socket read `getpeercert()` (cert dict) and `version()`
   (negotiated protocol string).
4. Parse the cert's `notAfter` with `ssl.cert_time_to_seconds()` → epoch;
   compare to `time.time()` for days-until-expiry.
5. Catch `ssl.SSLCertVerificationError`: set `valid: False`, put the reason in
   `error` — an expired/self-signed cert is a *finding*, not a crash.
6. Return `{host, valid, protocol, not_after, days_until_expiry, issuer,
   subject, error}`.

**Concepts/gotchas:** the finding-vs-exception distinction matters most here;
`getpeercert()` returns `{}` on an unverified connection, so verification and
cert-reading interact; no cipher enumeration / downgrade probing — only read
what the server negotiated.

**Docs:** ssl module (create_default_context, wrap_socket, getpeercert,
cert_time_to_seconds, SSLCertVerificationError)
https://docs.python.org/3/library/ssl.html · socket.create_connection
https://docs.python.org/3/library/socket.html#socket.create_connection ·
time.time https://docs.python.org/3/library/time.html#time.time

**Verify:** `python -m sitecheck.cli example.com --checks tls` (valid); for the
failure path try `expired.badssl.com` or `self-signed.badssl.com` and confirm
you get `valid: False` with a reason, not a traceback.

---

## 7. `sitecheck/report.py` → `save_report`
**What:** write a built report to disk as markdown or json; return the Path.

**Hint steps:**
1. `Path(directory).mkdir(parents=True, exist_ok=True)`.
2. Build a safe filename like `{domain}.{fmt}`; sanitize the domain (replace
   `/`, `:`, etc.) so weird input can't escape the directory. Optionally add a
   timestamp for history.
3. `fmt == "json"` → `json.dumps(report, indent=2)`.
4. `fmt == "md"` → render a readable doc: title with domain, the severity
   counts, then findings grouped/ordered by severity.
5. Write UTF-8, return the `Path`. Raise a clear `ValueError` on unknown `fmt`.

**Concepts/gotchas:** path traversal safety on the filename; `pathlib` over
string paths; keep rendering separate from `build_report`'s logic.

**Docs:** pathlib https://docs.python.org/3/library/pathlib.html · json.dumps
https://docs.python.org/3/library/json.html#json.dumps · GitHub-flavored
markdown tables https://docs.github.com/en/get-started/writing-on-github

**Verify:** run any full scan (`python -m sitecheck.cli example.com`), open the
file under `reports/`, then re-run with `--format json` and confirm both
render. (`reports/` is gitignored — it won't be committed.)

---

## When everything's implemented
- `pytest` is green.
- A full run produces a real `reports/<domain>.{md,json}` with ranked findings.
- Try `testphp.vulnweb.com` for a target that actually trips findings.
- Reminder: only scan domains you own or have permission to test.
