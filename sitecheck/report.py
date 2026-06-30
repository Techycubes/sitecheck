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

    def add(severity, category, check, title, detail):
        findings.append({
            "severity": severity,
            "category": category,
            "check": check,
            "title": title,
            "detail": detail,
        })

    # ===================== SECURITY ======================================

    # --- exposed files: any served sensitive path is high severity -------
    exposed = results.get("exposed_files", {})
    if not exposed.get("error"):
        for item in exposed.get("exposed", []):
            path = item.get("path", "?")
            code = item.get("status_code", "?")
            add("high", "security", "exposed_files",
                f"Exposed file: {path}", f"Returned HTTP {code}")

    # --- TLS: invalid/expired cert is high, near-expiry is medium --------
    tls = results.get("tls", {})
    if not tls.get("error"):
        if tls.get("valid") is False:
            add("high", "security", "tls", "Invalid TLS certificate",
                tls.get("error") or "Certificate failed verification.")
        else:
            days = tls.get("days_until_expiry")
            if isinstance(days, int) and days < 30:
                add("medium", "security", "tls",
                    "TLS certificate expiring soon",
                    f"{days} day(s) until expiry.")

    # --- security headers: each missing recommended header is medium -----
    headers = results.get("headers", {})
    if not headers.get("error"):
        for name in headers.get("missing", []):
            add("medium", "security", "headers", f"Missing header: {name}",
                "Recommended security header not present in the response.")

    # --- email auth DNS: missing SPF (medium) / DMARC (low) --------------
    dns = results.get("dns", {})
    if not dns.get("error"):
        if dns.get("spf", {}).get("present") is False:
            add("medium", "security", "dns", "Missing SPF record",
                "No v=spf1 TXT record found on the domain.")
        if dns.get("dmarc", {}).get("present") is False:
            add("low", "security", "dns", "Missing DMARC record",
                "No v=DMARC1 TXT record found at _dmarc.<domain>.")

    # --- security.txt: informational if absent ---------------------------
    sec = results.get("security_txt", {})
    if not sec.get("error") and sec.get("present") is False:
        add("low", "security", "security_txt", "No security.txt published",
            "Site does not expose /.well-known/security.txt (RFC 9116).")

    # ========================= SEO =======================================

    # --- title & meta description ----------------------------------------
    meta = results.get("meta", {})
    if not meta.get("error"):
        if not meta.get("title"):
            add("medium", "seo", "meta", "Missing <title>",
                "The page has no <title> element.")
        else:
            tl = meta.get("title_length", 0)
            if tl < 30 or tl > 60:
                add("low", "seo", "meta", "Title length outside 30-60 chars",
                    f"Title is {tl} characters.")
        if not meta.get("meta_description"):
            add("medium", "seo", "meta", "Missing meta description",
                "No <meta name=\"description\"> on the page.")
        else:
            dl = meta.get("description_length", 0)
            if dl < 120 or dl > 160:
                add("low", "seo", "meta",
                    "Meta description outside 120-160 chars",
                    f"Description is {dl} characters.")

    # --- robots.txt & sitemap --------------------------------------------
    rs = results.get("robots_sitemap", {})
    if not rs.get("error"):
        robots = rs.get("robots", {})
        if robots.get("blocks_all"):
            add("high", "seo", "robots_sitemap",
                "robots.txt blocks all crawlers",
                "A blanket 'Disallow: /' for User-agent: * stops indexing.")
        elif not robots.get("present"):
            add("low", "seo", "robots_sitemap", "No robots.txt",
                "Site does not serve /robots.txt.")
        if not rs.get("sitemap", {}).get("present"):
            add("low", "seo", "robots_sitemap", "No XML sitemap found",
                "Neither a robots.txt Sitemap: directive nor /sitemap.xml.")

    # --- indexability & canonical ----------------------------------------
    idx = results.get("indexability", {})
    if not idx.get("error"):
        if idx.get("noindex_meta") or idx.get("noindex_header"):
            add("high", "seo", "indexability", "Page set to noindex",
                "A meta robots tag or X-Robots-Tag header blocks indexing.")
        if not idx.get("canonical"):
            add("low", "seo", "indexability", "No canonical URL",
                "No <link rel=\"canonical\"> on the page.")
        if not idx.get("html_lang"):
            add("low", "seo", "indexability", "No <html lang> attribute",
                "Declaring the page language helps search engines.")
        if not idx.get("viewport"):
            add("low", "seo", "indexability", "No viewport meta",
                "Missing <meta name=\"viewport\"> (mobile-friendliness).")

    # --- social & structured data ----------------------------------------
    soc = results.get("social", {})
    if not soc.get("error"):
        missing_og = [k for k, v in soc.get("open_graph", {}).items() if not v]
        if missing_og:
            add("low", "seo", "social",
                "Missing Open Graph tags",
                f"Absent: {', '.join(missing_og)}.")
        if not soc.get("twitter_card"):
            add("low", "seo", "social", "No twitter:card meta",
                "No Twitter Card markup for rich link previews.")
        if not soc.get("structured_data_count"):
            add("low", "seo", "social", "No structured data",
                "No JSON-LD (<script type=\"application/ld+json\">) found.")

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


# Human-readable section titles, in the order they should appear.
CATEGORY_TITLES = (("security", "Security"), ("seo", "SEO"))


def _render_markdown(report):
    """Render a built report dict as Markdown, grouped by category."""
    domain = report.get("domain", "?")
    counts = report.get("counts", {})
    findings = report.get("findings", [])

    lines = [
        f"# sitecheck report: {domain}",
        "",
        (
            f"**Total findings:** {counts.get('high', 0)} high · "
            f"{counts.get('medium', 0)} medium · {counts.get('low', 0)} low"
        ),
        "",
    ]

    if not findings:
        lines.append("_No findings._")
        return "\n".join(lines) + "\n"

    # Build the category order: known categories first, then any extras.
    known = [cat for cat, _ in CATEGORY_TITLES]
    titles = dict(CATEGORY_TITLES)
    extra = [f.get("category", "other") for f in findings if f.get("category") not in known]
    order = known + sorted(set(extra))

    for cat in order:
        group = [f for f in findings if f.get("category", "other") == cat]
        if not group:
            continue
        high = sum(1 for f in group if f.get("severity") == "high")
        medium = sum(1 for f in group if f.get("severity") == "medium")
        low = sum(1 for f in group if f.get("severity") == "low")

        lines.append(f"## {titles.get(cat, cat.title())}")
        lines.append("")
        lines.append(f"_{high} high · {medium} medium · {low} low_")
        lines.append("")
        lines.append("| Severity | Check | Finding | Detail |")
        lines.append("| --- | --- | --- | --- |")
        for finding in group:
            sev = finding.get("severity", "")
            check = finding.get("check", "")
            title = str(finding.get("title", "")).replace("|", "\\|")
            detail = str(finding.get("detail", "")).replace("|", "\\|")
            lines.append(f"| {sev} | {check} | {title} | {detail} |")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
