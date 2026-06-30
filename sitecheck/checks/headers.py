"""Check for the presence of recommended HTTP security headers."""

import requests  # noqa: F401  (you'll use this in your implementation)

# The security headers we care about. Keys are the canonical header names
# (case-insensitive when you compare against the response). Feel free to turn
# these into richer objects later (e.g. to validate the *value*, not just
# presence), but presence/absence is enough for a first pass.
SECURITY_HEADERS = (
    "Strict-Transport-Security",   # HSTS
    "Content-Security-Policy",     # CSP
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


def check_headers(domain, user_agent):
    """Inspect a site's HTTP response headers for security headers.

    Args:
        domain: Bare domain or hostname, e.g. ``"example.com"`` (no scheme).
        user_agent: User-Agent string to send with the request.

    Returns:
        A dict summarizing the result. A suggested shape:
            {
                "url": "https://example.com",
                "status_code": 200,
                "present": {"Content-Security-Policy": "<value>", ...},
                "missing": ["X-Frame-Options", ...],
                "error": None,
            }

    TODO (implement this yourself):
        1. Build the URL: default to ``https://{domain}``. Decide whether you
           want to follow redirects (requests does by default) and whether to
           record the final URL after redirects.
        2. Send a GET with ``headers={"User-Agent": user_agent}`` and a sane
           ``timeout`` (e.g. 10s). Wrap network errors and either return them
           in an ``"error"`` field or let them propagate for the CLI to catch.
        3. Compare ``response.headers`` (a case-insensitive dict) against
           ``SECURITY_HEADERS``. Build a ``present`` map (header -> value) and
           a ``missing`` list.
        4. Return the summary dict. Keep it JSON-serializable (str/int/list/
           dict/bool/None only) so report.py can dump it straight to JSON.

    Note: this is a passive check. One GET, no fuzzing, no header injection.
    """
    url = f"https://{domain}"
    try:
        response = requests.get(
            url, headers={"User-Agent": user_agent}, timeout=10
        )
    except requests.exceptions.RequestException as exc:
        return {
            "url": url,
            "status_code": None,
            "present": {},
            "missing": list(SECURITY_HEADERS),
            "error": f"{type(exc).__name__}: {exc}",
        }

    # response.headers is a case-insensitive dict, so membership/lookup by the
    # canonical names works regardless of how the server cased them.
    present = {}
    missing = []
    for name in SECURITY_HEADERS:
        if name in response.headers:
            present[name] = response.headers[name]
        else:
            missing.append(name)

    return {
        "url": response.url,  # final URL after any redirects
        "status_code": response.status_code,
        "present": present,
        "missing": missing,
        "error": None,
    }
