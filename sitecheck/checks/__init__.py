"""Individual passive check modules.

Each module exposes a single function that takes a domain (and sometimes a
user-agent string) and returns a plain ``dict`` describing what it found.
The functions never raise on a "finding"; a missing header or an expiring
cert is normal data, not an error. They only raise for genuine operational
failures (e.g. the host is unreachable), and the CLI catches those.

Security check functions:
    check_headers(domain, user_agent) -> dict
    check_tls(domain) -> dict
    check_dns(domain) -> dict
    check_security_txt(domain, user_agent) -> dict
    check_exposed_files(domain, user_agent) -> dict

SEO check functions:
    check_meta(domain, user_agent) -> dict
    check_robots_sitemap(domain, user_agent) -> dict
    check_indexability(domain, user_agent) -> dict
    check_social(domain, user_agent) -> dict
"""

from .headers import check_headers
from .tls import check_tls
from .dns_records import check_dns
from .security_txt import check_security_txt
from .exposed_files import check_exposed_files
from .seo_meta import check_meta
from .seo_robots import check_robots_sitemap
from .seo_indexability import check_indexability
from .seo_social import check_social

__all__ = [
    "check_headers",
    "check_tls",
    "check_dns",
    "check_security_txt",
    "check_exposed_files",
    "check_meta",
    "check_robots_sitemap",
    "check_indexability",
    "check_social",
]
