"""Tests for sitecheck.report.build_report.

These are your target while implementing ``sitecheck/report.py``. The fake
input data below mimics what the (still-stubbed) check functions are documented
to return. Run with::

    pytest

Both tests will fail with NotImplementedError until you implement
``build_report``. Implement it until they pass, then flesh out ``save_report``.
"""

from sitecheck.report import build_report

# --- Fake check results, shaped like the real check functions' output. -------

# A site missing the Content-Security-Policy header (others present).
FAKE_RESULTS_MISSING_HEADER = {
    "headers": {
        "url": "https://example.com",
        "status_code": 200,
        "present": {
            "Strict-Transport-Security": "max-age=63072000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        },
        "missing": ["Content-Security-Policy"],
        "error": None,
    },
    "tls": {
        "host": "example.com",
        "valid": True,
        "protocol": "TLSv1.3",
        "not_after": "Jun 24 12:00:00 2027 GMT",
        "days_until_expiry": 365,
        "error": None,
    },
    "dns": {
        "domain": "example.com",
        "spf": {"present": True, "record": "v=spf1 -all"},
        "dmarc": {"present": True, "record": "v=DMARC1; p=reject"},
        "error": None,
    },
    "security_txt": {
        "url": "https://example.com/.well-known/security.txt",
        "present": True,
        "contacts": ["mailto:security@example.com"],
        "error": None,
    },
    "exposed_files": {
        "base_url": "https://example.com",
        "exposed": [],
        "checked": ["/.env", "/.git/config"],
        "error": None,
    },
}

# A site with an exposed /.env file.
FAKE_RESULTS_EXPOSED_FILE = {
    "headers": {
        "url": "https://leaky.example",
        "status_code": 200,
        "present": {
            "Strict-Transport-Security": "max-age=63072000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        },
        "missing": [],
        "error": None,
    },
    "exposed_files": {
        "base_url": "https://leaky.example",
        "exposed": [{"path": "/.env", "status_code": 200}],
        "checked": ["/.env", "/.git/config"],
        "error": None,
    },
}


def _all_titles(report):
    """Helper: lower-cased concatenation of every finding's title + detail."""
    parts = []
    for finding in report.get("findings", []):
        parts.append(str(finding.get("title", "")))
        parts.append(str(finding.get("detail", "")))
    return " ".join(parts).lower()


def test_build_report_flags_missing_header():
    """A missing security header should surface as a finding."""
    report = build_report("example.com", FAKE_RESULTS_MISSING_HEADER)

    assert report["domain"] == "example.com"
    assert report["findings"], "expected at least one finding"

    # Some finding should mention the missing Content-Security-Policy header.
    assert "content-security-policy" in _all_titles(report)


def test_build_report_flags_exposed_file():
    """An exposed /.env file should surface as a (high-severity) finding."""
    report = build_report("leaky.example", FAKE_RESULTS_EXPOSED_FILE)

    assert report["findings"], "expected at least one finding"

    env_findings = [
        f for f in report["findings"]
        if ".env" in str(f.get("title", "")).lower()
        or ".env" in str(f.get("detail", "")).lower()
    ]
    assert env_findings, "expected a finding for the exposed /.env file"
    assert env_findings[0]["severity"] == "high"


# --- SEO fake results, shaped like the SEO check functions' output. ----------

# A page with no <title> and a noindex meta robots tag.
FAKE_RESULTS_SEO = {
    "meta": {
        "url": "https://example.com",
        "title": None,
        "title_length": 0,
        "meta_description": "A perfectly fine description that sits within the "
                            "recommended one-hundred-and-twenty to one-sixty.",
        "description_length": 130,
        "error": None,
    },
    "indexability": {
        "noindex_meta": True,
        "noindex_header": False,
        "canonical": "https://example.com/",
        "html_lang": "en",
        "viewport": "width=device-width, initial-scale=1",
        "error": None,
    },
}


def test_build_report_flags_missing_title():
    """A missing <title> should surface as an SEO-category finding."""
    report = build_report("example.com", FAKE_RESULTS_SEO)

    title_findings = [
        f for f in report["findings"]
        if "title" in str(f.get("title", "")).lower()
    ]
    assert title_findings, "expected a finding for the missing <title>"
    assert title_findings[0]["category"] == "seo"


def test_build_report_flags_noindex_high():
    """A noindex page should surface as a high-severity SEO finding."""
    report = build_report("example.com", FAKE_RESULTS_SEO)

    noindex_findings = [
        f for f in report["findings"]
        if "noindex" in str(f.get("title", "")).lower()
    ]
    assert noindex_findings, "expected a finding for the noindex page"
    assert noindex_findings[0]["severity"] == "high"
    assert noindex_findings[0]["category"] == "seo"
