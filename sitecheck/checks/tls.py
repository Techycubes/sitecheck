"""Check a domain's TLS certificate and negotiated protocol version."""

import ssl       # noqa: F401  (you'll use this in your implementation)
import socket    # noqa: F401  (you'll use this in your implementation)

# Standard HTTPS port. Kept as a constant so you can parameterize later.
HTTPS_PORT = 443


def check_tls(domain):
    """Open a TLS connection and report on the server certificate.

    Args:
        domain: Bare domain or hostname, e.g. ``"example.com"`` (no scheme,
            no port).

    Returns:
        A dict summarizing the certificate and connection. A suggested shape:
            {
                "host": "example.com",
                "valid": True,             # did the handshake verify OK?
                "protocol": "TLSv1.3",     # negotiated version
                "not_after": "Jun 24 12:00:00 2026 GMT",
                "days_until_expiry": 87,
                "issuer": "...",           # optional, nice to have
                "subject": "...",          # optional, nice to have
                "error": None,             # or a message if the handshake failed
            }

    TODO (implement this yourself):
        1. Create a default SSL context with ``ssl.create_default_context()``.
           This verifies the cert chain and hostname for you.
        2. Open a TCP socket to ``(domain, HTTPS_PORT)`` with a timeout, then
           wrap it: ``context.wrap_socket(sock, server_hostname=domain)``.
           Use ``with`` blocks so sockets always close.
        3. From the wrapped socket, call ``ssock.getpeercert()`` for the cert
           dict and ``ssock.version()`` for the negotiated protocol string.
        4. Parse the cert's ``"notAfter"`` field. It's a string like
           ``"Jun 24 12:00:00 2026 GMT"``; ``ssl.cert_time_to_seconds()`` turns
           it into an epoch you can compare against ``time.time()`` to get
           days-until-expiry.
        5. If the handshake fails verification (``ssl.SSLCertVerificationError``)
           catch it, set ``"valid": False``, and put the reason in ``"error"``.
           A self-signed or expired cert is a *finding*, not a crash.

    Note: this only does a TLS handshake. No cipher enumeration, no probing
    for weak protocol downgrades beyond reading what the server negotiated.
    """
    raise NotImplementedError("check_tls: see TODO in this file")
