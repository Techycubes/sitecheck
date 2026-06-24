"""sitecheck - a passive, non-intrusive security audit CLI tool.

This package only performs read-only, low-impact checks against a target
domain (HTTP GETs/HEADs, a TLS handshake, and DNS lookups). It never scans
ports, never attempts exploitation, and never auto-submits anything anywhere.
See the README for the full list of things this tool deliberately does NOT do.
"""

__version__ = "0.1.0"
