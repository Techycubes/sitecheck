"""Turn raw check results into a ranked report and write it to disk.

This module is intentionally left as stubs -- ``tests/test_report.py`` is your
target. Implement ``build_report`` until those tests pass, then implement
``save_report``.
"""

import json
from pathlib import Path

# Severity ordering, highest first. Use these strings as your severity values
# so the report is consistent and sortable.
SEVERITY_ORDER = ("high", "medium", "low")


def build_report(domain, results):
    """Turn raw per-check results into a severity-ranked summary.

    Args:
        domain: The domain these results belong to, e.g. ``"example.com"``.
        results: A dict mapping check name -> that check's raw return dict, e.g.
            {
                "headers": {... output of check_headers ...},
                "tls": {... output of check_tls ...},
                "dns": {...},
                "security_txt": {...},
                "exposed_files": {...},
            }
            (See ``tests/test_report.py`` for concrete example input.)

    Returns:
        A dict summarizing findings. A suggested shape:
            {
                "domain": "example.com",
                "findings": [
                    {
                        "severity": "high",
                        "check": "exposed_files",
                        "title": "Exposed file: /.env",
                        "detail": "Returned HTTP 200",
                    },
                    {
                        "severity": "medium",
                        "check": "headers",
                        "title": "Missing header: Content-Security-Policy",
                        "detail": "...",
                    },
                    ...
                ],
                "counts": {"high": 1, "medium": 3, "low": 0},
            }
        ``findings`` should be sorted by severity using ``SEVERITY_ORDER``.

    TODO (implement this yourself):
        1. Walk each check's raw result and translate it into zero or more
           finding dicts. Decide your own severity mapping, for example:
             - exposed_files: any exposed path        -> high
             - tls: invalid cert / expired / expiring  -> high / medium
             - headers: each missing security header   -> medium (or low)
             - dns: missing SPF or DMARC               -> medium / low
             - security_txt: absent                    -> low (informational)
           The two tests that ship with the scaffold assert that (a) a missing
           security header produces a finding and (b) an exposed file produces
           a finding -- so make sure those two paths definitely emit findings.
        2. Be defensive: a check may have errored and its result may contain an
           ``"error"`` key instead of data. Don't crash on missing keys; use
           ``.get()``.
        3. Sort ``findings`` by severity (high -> low). ``SEVERITY_ORDER.index``
           makes a handy sort key.
        4. Tally ``counts`` per severity and return the report dict.
    """
    findings = []

    # --- exposed files: any served sensitive path is high severity -------
    exposed = results.get("exposed_files", {})
    if not exposed.get("error"):
        for item in exposed.get("exposed", []):
            path = item.get("path", "?")
            code = item.get("status_code", "?")
            findings.append({
                "severity": "high",
                "check": "exposed_files",
                "title": f"Exposed file: {path}",
                "detail": f"Returned HTTP {code}",
            })

    # --- TLS: invalid/expired cert is high, near-expiry is medium --------
    tls = results.get("tls", {})
    if not tls.get("error"):
        if tls.get("valid") is False:
            findings.append({
                "severity": "high",
                "check": "tls",
                "title": "Invalid TLS certificate",
                "detail": tls.get("error") or "Certificate failed verification.",
            })
        else:
            days = tls.get("days_until_expiry")
            if isinstance(days, int) and days < 30:
                findings.append({
                    "severity": "medium",
                    "check": "tls",
                    "title": "TLS certificate expiring soon",
                    "detail": f"{days} day(s) until expiry.",
                })

    # --- security headers: each missing recommended header is medium -----
    headers = results.get("headers", {})
    if not headers.get("error"):
        for name in headers.get("missing", []):
            findings.append({
                "severity": "medium",
                "check": "headers",
                "title": f"Missing header: {name}",
                "detail": "Recommended security header not present in the response.",
            })

    # --- email auth DNS: missing SPF (medium) / DMARC (low) --------------
    dns = results.get("dns", {})
    if not dns.get("error"):
        if dns.get("spf", {}).get("present") is False:
            findings.append({
                "severity": "medium",
                "check": "dns",
                "title": "Missing SPF record",
                "detail": "No v=spf1 TXT record found on the domain.",
            })
        if dns.get("dmarc", {}).get("present") is False:
            findings.append({
                "severity": "low",
                "check": "dns",
                "title": "Missing DMARC record",
                "detail": "No v=DMARC1 TXT record found at _dmarc.<domain>.",
            })

    # --- security.txt: informational if absent ---------------------------
    sec = results.get("security_txt", {})
    if not sec.get("error") and sec.get("present") is False:
        findings.append({
            "severity": "low",
            "check": "security_txt",
            "title": "No security.txt published",
            "detail": "Site does not expose /.well-known/security.txt (RFC 9116).",
        })

    # Highest severity first; stable within a severity band.
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] += 1

    return {"domain": domain, "findings": findings, "counts": counts}


def save_report(domain, report, directory, fmt):
    """Write a built report to disk as markdown or JSON.

    Args:
        domain: The domain the report is for (used in the filename).
        report: The dict returned by ``build_report``.
        directory: Destination directory (str or Path), e.g. ``"reports"``.
        fmt: Either ``"md"`` or ``"json"``.

    Returns:
        The ``pathlib.Path`` of the file that was written.

    TODO (implement this yourself):
        1. Ensure ``directory`` exists (``Path(directory).mkdir(parents=True,
           exist_ok=True)``).
        2. Build a safe filename, e.g. ``{domain}.{fmt}`` (sanitize the domain
           -- replace ``/`` and ``:`` etc. -- so weird input can't escape the
           directory). Consider adding a timestamp if you want history.
        3. For ``fmt == "json"``: ``json.dumps(report, indent=2)``.
           For ``fmt == "md"``: render a readable markdown document -- a title
           with the domain, the severity counts, then a section/table listing
           each finding. Group or order by severity.
        4. Write the file (UTF-8) and return its Path.
        5. Raise a clear ``ValueError`` for an unsupported ``fmt``.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    # Sanitize the domain so nothing in it can escape the output directory.
    safe = "".join(c if (c.isalnum() or c in "-._") else "_" for c in domain)
    safe = safe.strip("._") or "report"

    if fmt == "json":
        path = directory / f"{safe}.json"
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return path
    if fmt == "md":
        path = directory / f"{safe}.md"
        path.write_text(_render_markdown(report), encoding="utf-8")
        return path

    raise ValueError(f"Unsupported format: {fmt!r} (expected 'md' or 'json')")


def _render_markdown(report):
    """Render a built report dict as a readable Markdown document."""
    domain = report.get("domain", "?")
    counts = report.get("counts", {})
    findings = report.get("findings", [])

    lines = [
        f"# Security report: {domain}",
        "",
        (
            f"**Findings:** {counts.get('high', 0)} high · "
            f"{counts.get('medium', 0)} medium · {counts.get('low', 0)} low"
        ),
        "",
    ]

    if not findings:
        lines.append("_No findings._")
        return "\n".join(lines) + "\n"

    lines.append("| Severity | Check | Finding | Detail |")
    lines.append("| --- | --- | --- | --- |")
    for finding in findings:
        sev = finding.get("severity", "")
        check = finding.get("check", "")
        title = str(finding.get("title", "")).replace("|", "\\|")
        detail = str(finding.get("detail", "")).replace("|", "\\|")
        lines.append(f"| {sev} | {check} | {title} | {detail} |")

    return "\n".join(lines) + "\n"
