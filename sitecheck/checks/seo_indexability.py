"""SEO check: whether the homepage can be indexed, plus key page signals."""

from ._html import fetch_html


def check_indexability(domain, user_agent):
    """Report indexability signals: noindex, canonical, lang, viewport.

    Returns a dict like::

        {
            "noindex_meta": False,    # <meta name="robots" content="noindex">
            "noindex_header": False,  # X-Robots-Tag: noindex response header
            "canonical": "https://example.com/",
            "html_lang": "en",
            "viewport": "width=device-width, initial-scale=1",
            "error": None,
        }

    ``noindex`` (by meta tag or header) is the highest-impact finding here: it
    tells search engines not to index the page at all.
    """
    response, soup, error = fetch_html(domain, user_agent)
    if error:
        return {
            "noindex_meta": None,
            "noindex_header": None,
            "canonical": None,
            "html_lang": None,
            "viewport": None,
            "error": error,
        }

    # meta robots noindex
    noindex_meta = False
    robots_meta = soup.find("meta", attrs={"name": "robots"})
    if robots_meta and robots_meta.get("content"):
        noindex_meta = "noindex" in robots_meta["content"].lower()

    # X-Robots-Tag response header noindex
    xrobots = response.headers.get("X-Robots-Tag", "")
    noindex_header = "noindex" in xrobots.lower()

    # rel=canonical
    canonical = None
    canonical_tag = soup.find("link", attrs={"rel": "canonical"})
    if canonical_tag and canonical_tag.get("href"):
        canonical = canonical_tag["href"].strip()

    # <html lang="...">
    html_lang = soup.html.get("lang") if soup.html else None

    # viewport meta (mobile-friendliness signal)
    viewport = None
    viewport_tag = soup.find("meta", attrs={"name": "viewport"})
    if viewport_tag and viewport_tag.get("content"):
        viewport = viewport_tag["content"].strip()

    return {
        "noindex_meta": noindex_meta,
        "noindex_header": noindex_header,
        "canonical": canonical,
        "html_lang": html_lang,
        "viewport": viewport,
        "error": None,
    }
