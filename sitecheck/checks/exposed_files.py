"""Check for a small fixed list of commonly-exposed sensitive files."""

import requests  # noqa: F401  (you'll use this in your implementation)

# A SMALL, fixed allow-list of well-known sensitive paths. This is deliberately
# tiny and static -- it is NOT a fuzzing wordlist. Do not expand this into a
# directory brute-forcer; that crosses the line from "passive audit" into
# "intrusive scan". One HEAD per path, that's it.
SENSITIVE_PATHS = (
    "/.env",
    "/.git/config",
    "/.aws/credentials",
    "/.htpasswd",
    "/config.php.bak",
    "/.DS_Store",
    "/backup.zip",
    "/wp-config.php.bak",
)


def check_exposed_files(domain, user_agent):
    """HEAD a fixed list of sensitive paths and flag any that return 200.

    Args:
        domain: Bare domain or hostname, e.g. ``"example.com"``.
        user_agent: User-Agent string to send with the request.

    Returns:
        A dict summarizing the result. A suggested shape:
            {
                "base_url": "https://example.com",
                "exposed": [
                    {"path": "/.env", "status_code": 200},
                ],
                "checked": ["/.env", "/.git/config", ...],
                "error": None,
            }

    TODO (implement this yourself):
        1. For each path in ``SENSITIVE_PATHS``, build ``https://{domain}{path}``
           and send a HEAD request (cheaper than GET; you only need the status
           line) with the user_agent and a timeout.
        2. A 200 means the file is very likely exposed -> add it to ``exposed``.
           Be a little careful: some servers return 200 for everything with a
           soft-404 body. Since you're using HEAD you can't see the body, so
           keep it simple for now and just trust the status code -- note this
           limitation. You can refine later.
        3. Decide how to handle redirects. A 301/302 to a login or homepage is
           NOT an exposure; consider ``allow_redirects=False`` so you see the
           real status of the path itself.
        4. Catch per-request network errors so one bad path doesn't abort the
           whole list; record them but keep going.
        5. Return the summary dict, JSON-serializable.

    Note: passive footprint -- a handful of HEAD requests to fixed paths. No
    downloading of the files, no exploitation of anything found. Finding a file
    means reporting it, nothing more.
    """
    base_url = f"https://{domain}"
    exposed = []
    errors = []

    for path in SENSITIVE_PATHS:
        url = base_url + path
        try:
            # HEAD is enough -- we only need the status line, not the body.
            # allow_redirects=False so a 301/302 to a login/homepage isn't
            # mistaken for the path itself being served.
            response = requests.head(
                url,
                headers={"User-Agent": user_agent},
                timeout=10,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as exc:
            errors.append({"path": path, "error": f"{type(exc).__name__}: {exc}"})
            continue

        if response.status_code == 200:
            # NOTE: with HEAD we can't see the body, so we can't rule out a
            # server that soft-404s with a 200. We trust the status code here.
            exposed.append({"path": path, "status_code": response.status_code})

    return {
        "base_url": base_url,
        "exposed": exposed,
        "checked": list(SENSITIVE_PATHS),
        "errors": errors,
        "error": None,
    }
