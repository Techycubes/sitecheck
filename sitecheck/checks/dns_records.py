"""Check a domain's email-authentication DNS records (SPF and DMARC)."""

import dns.resolver
import dns.exception


def check_dns(domain):
    """Look up SPF and DMARC TXT records for a domain.

    Args:
        domain: Bare domain, e.g. ``"example.com"``.

    Returns:
        A dict summarizing what was found. A suggested shape:
            {
                "domain": "example.com",
                "spf": {
                    "present": True,
                    "record": "v=spf1 include:_spf.google.com ~all",
                },
                "dmarc": {
                    "present": False,
                    "record": None,
                },
                "error": None,
            }

    TODO (implement this yourself):
        1. SPF lives in a TXT record on the *apex* domain. Query
           ``dns.resolver.resolve(domain, "TXT")`` and look through the answers
           for the one that starts with ``"v=spf1"``. Note: TXT records come
           back as quoted byte-string chunks; you'll want to join/decode them
           (e.g. ``b"".join(rdata.strings).decode()``).
        2. DMARC lives in a TXT record on the ``_dmarc.<domain>`` subdomain.
           Query ``dns.resolver.resolve("_dmarc." + domain, "TXT")`` and look
           for the answer starting with ``"v=DMARC1"``.
        3. Handle the "no record" cases cleanly. ``dns.resolver.NXDOMAIN`` and
           ``dns.resolver.NoAnswer`` mean "not configured" -> ``present: False``,
           not an error. ``dns.resolver.NoNameservers`` / ``Timeout`` are real
           errors -> populate ``"error"``.
        4. Return the summary dict, JSON-serializable.

    Note: read-only DNS lookups only. No zone transfers, no brute-forcing
    subdomains.
    """
    result = {
        "domain": domain,
        "spf": {"present": False, "record": None},
        "dmarc": {"present": False, "record": None},
        "error": None,
    }

    def _find_txt(name, marker):
        """Return the first TXT record (decoded) starting with marker, or None.

        Raises on genuine resolver failures; returns None when the name simply
        has no such record (NXDOMAIN / NoAnswer).
        """
        try:
            answers = dns.resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        for rdata in answers:
            # TXT data comes back as one or more byte-string chunks.
            txt = b"".join(rdata.strings).decode(errors="replace")
            if txt.lower().startswith(marker):
                return txt
        return None

    try:
        spf = _find_txt(domain, "v=spf1")
        if spf is not None:
            result["spf"] = {"present": True, "record": spf}

        dmarc = _find_txt("_dmarc." + domain, "v=dmarc1")
        if dmarc is not None:
            result["dmarc"] = {"present": True, "record": dmarc}
    except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    return result
