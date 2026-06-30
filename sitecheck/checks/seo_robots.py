"""SEO check: robots.txt and sitemap.xml presence and basic sanity."""

import requests

ROBOTS_PATH = "/robots.txt"
SITEMAP_PATH = "/sitemap.xml"


def check_robots_sitemap(domain, user_agent):
    """Fetch /robots.txt and /sitemap.xml and summarize them.

    Returns a dict like::

        {
            "robots": {
                "present": True,
                "blocks_all": False,         # a blanket "Disallow: /" for *
                "sitemaps": ["https://example.com/sitemap.xml"],
            },
            "sitemap": {"present": True, "url": "...", "url_count": 42},
            "error": None,
        }

    Passive: two GETs to fixed, well-known paths. No crawling of the URLs found
    inside the sitemap.
    """
    headers = {"User-Agent": user_agent}
    base = f"https://{domain}"
    result = {
        "robots": {"present": False, "blocks_all": False, "sitemaps": []},
        "sitemap": {"present": False, "url": None, "url_count": 0},
        "error": None,
    }

    # --- robots.txt ------------------------------------------------------
    try:
        r = requests.get(base + ROBOTS_PATH, headers=headers, timeout=10)
    except requests.exceptions.RequestException as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    if r.status_code == 200 and r.text.strip():
        result["robots"]["present"] = True
        result["robots"]["blocks_all"] = _robots_blocks_all(r.text)
        result["robots"]["sitemaps"] = _robots_sitemaps(r.text)

    # --- sitemap.xml -----------------------------------------------------
    # Prefer a Sitemap: directive from robots.txt; fall back to /sitemap.xml.
    sitemap_url = (
        result["robots"]["sitemaps"][0]
        if result["robots"]["sitemaps"]
        else base + SITEMAP_PATH
    )
    try:
        s = requests.get(sitemap_url, headers=headers, timeout=10)
    except requests.exceptions.RequestException:
        # A missing sitemap is a finding, not a run-ending error.
        return result

    if s.status_code == 200 and "<" in s.text:
        result["sitemap"]["present"] = True
        result["sitemap"]["url"] = sitemap_url
        # Cheap count without a full XML parse: <url> entries in a urlset, or
        # <sitemap> entries in a sitemap index.
        result["sitemap"]["url_count"] = (
            s.text.count("<url>") + s.text.count("<sitemap>")
        )

    return result


def _robots_blocks_all(text):
    """True if the wildcard user-agent group has a blanket ``Disallow: /``."""
    in_star_group = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if field == "user-agent":
            in_star_group = value == "*"
        elif field == "disallow" and in_star_group and value == "/":
            return True
    return False


def _robots_sitemaps(text):
    """Collect every ``Sitemap:`` URL declared in robots.txt."""
    sitemaps = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        field, sep, value = line.partition(":")
        if sep and field.strip().lower() == "sitemap":
            url = value.strip()
            if url:
                sitemaps.append(url)
    return sitemaps
