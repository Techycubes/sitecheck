"""SEO check: page <title> and <meta name="description">."""

from ._html import fetch_html

# Rough length guidance most SEO tools agree on (characters).
TITLE_MIN, TITLE_MAX = 30, 60
DESC_MIN, DESC_MAX = 120, 160


def check_meta(domain, user_agent):
    """Inspect the homepage's title and meta description.

    Returns a dict like::

        {
            "url": "https://example.com",
            "title": "Example Domain",
            "title_length": 14,
            "meta_description": None,
            "description_length": 0,
            "error": None,
        }

    A missing/over-long title or description is a *finding* (reported by
    ``report.build_report``), not an error. Only a network failure sets
    ``"error"``.
    """
    response, soup, error = fetch_html(domain, user_agent)
    if error:
        return {
            "url": f"https://{domain}",
            "title": None,
            "title_length": 0,
            "meta_description": None,
            "description_length": 0,
            "error": error,
        }

    title = soup.title.string.strip() if soup.title and soup.title.string else None

    desc_tag = soup.find("meta", attrs={"name": "description"})
    description = None
    if desc_tag and desc_tag.get("content"):
        description = desc_tag["content"].strip()

    return {
        "url": response.url,
        "title": title,
        "title_length": len(title) if title else 0,
        "meta_description": description,
        "description_length": len(description) if description else 0,
        "error": None,
    }
