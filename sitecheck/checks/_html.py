"""Shared helper for the HTML-based SEO checks.

The ``meta``, ``indexability`` and ``social`` checks all need the same thing:
the homepage HTML, parsed once. This module centralizes that single passive GET
so they fetch and parse consistently (and so the request logic lives in one
place rather than being copy-pasted three times).
"""

import requests
from bs4 import BeautifulSoup


def fetch_html(domain, user_agent):
    """GET ``https://{domain}`` and parse it with BeautifulSoup.

    Args:
        domain: Bare domain or hostname, e.g. ``"example.com"`` (no scheme).
        user_agent: User-Agent string to send with the request.

    Returns:
        A ``(response, soup, error)`` tuple:
            - On success: ``(requests.Response, BeautifulSoup, None)``.
            - On a network failure: ``(None, None, "<ErrType>: <msg>")`` so the
              caller can record it in its result's ``"error"`` field and keep
              the run going.

    Passive footprint: a single GET of the homepage. No crawling.
    """
    url = f"https://{domain}"
    try:
        response = requests.get(
            url, headers={"User-Agent": user_agent}, timeout=10
        )
    except requests.exceptions.RequestException as exc:
        return None, None, f"{type(exc).__name__}: {exc}"

    soup = BeautifulSoup(response.text, "html.parser")
    return response, soup, None
