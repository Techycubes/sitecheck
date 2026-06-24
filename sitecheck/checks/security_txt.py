"""Check for an RFC 9116 security.txt file and parse its contacts."""

import requests  # noqa: F401  (you'll use this in your implementation)

# RFC 9116 says the file lives under /.well-known/. The legacy top-level
# location is a documented fallback worth trying if the canonical one 404s.
WELL_KNOWN_PATH = "/.well-known/security.txt"
LEGACY_PATH = "/security.txt"


def check_security_txt(domain, user_agent):
    """Fetch and parse a domain's security.txt, if it has one.

    Args:
        domain: Bare domain or hostname, e.g. ``"example.com"``.
        user_agent: User-Agent string to send with the request.

    Returns:
        A dict summarizing the result. A suggested shape:
            {
                "url": "https://example.com/.well-known/security.txt",
                "present": True,
                "contacts": ["mailto:security@example.com", "https://..."],
                "fields": {"expires": "...", "policy": "...", ...},  # optional
                "error": None,
            }

    TODO (implement this yourself):
        1. Try ``https://{domain}{WELL_KNOWN_PATH}`` first with a GET (sending
           the user_agent and a timeout). If it 404s, optionally fall back to
           ``LEGACY_PATH``.
        2. Treat only a 200 with a text body as "present". Anything else ->
           ``present: False``.
        3. Parse the body line by line. security.txt is ``Field: value`` pairs,
           one per line; ``#`` lines are comments; blank lines are ignored.
           Field names are case-insensitive. Collect every ``Contact:`` value
           into a ``contacts`` list (there can be more than one, and order is
           significant per the RFC).
        4. (Optional) capture other useful fields like ``Expires``, ``Policy``,
           ``Encryption`` into a ``fields`` dict.
        5. Return the summary dict, JSON-serializable.

    IMPORTANT: This check only *reads and parses* security.txt. It must never
    contact the addresses it finds. Drafting a disclosure note from these
    contacts happens elsewhere (report/CLI layer) and only ever writes a file
    to ``outbox/`` for you to review and send manually.
    """
    raise NotImplementedError("check_security_txt: see TODO in this file")
