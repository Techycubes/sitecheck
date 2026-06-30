"""SEO check: social-share (Open Graph / Twitter) and structured data."""

from ._html import fetch_html

OG_PROPERTIES = ("og:title", "og:description", "og:image")


def check_social(domain, user_agent):
    """Report Open Graph, Twitter Card, and JSON-LD structured-data signals.

    Returns a dict like::

        {
            "open_graph": {"og:title": "...", "og:description": None, ...},
            "twitter_card": "summary_large_image",
            "structured_data_count": 1,   # <script type="application/ld+json">
            "error": None,
        }

    These drive richer search/social results. Their absence is low-severity
    (informational), never an error.
    """
    response, soup, error = fetch_html(domain, user_agent)
    if error:
        return {
            "open_graph": {prop: None for prop in OG_PROPERTIES},
            "twitter_card": None,
            "structured_data_count": 0,
            "error": error,
        }

    # Open Graph tags use the `property` attribute, not `name`.
    open_graph = {}
    for prop in OG_PROPERTIES:
        tag = soup.find("meta", attrs={"property": prop})
        open_graph[prop] = tag["content"].strip() if tag and tag.get("content") else None

    # Twitter Card
    twitter_card = None
    tw_tag = soup.find("meta", attrs={"name": "twitter:card"})
    if tw_tag and tw_tag.get("content"):
        twitter_card = tw_tag["content"].strip()

    # JSON-LD structured data blocks
    structured_data_count = len(
        soup.find_all("script", attrs={"type": "application/ld+json"})
    )

    return {
        "open_graph": open_graph,
        "twitter_card": twitter_card,
        "structured_data_count": structured_data_count,
        "error": None,
    }
