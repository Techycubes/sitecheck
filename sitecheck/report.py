"""Turn raw check results into a ranked report and write it to disk.

This module is intentionally left as stubs -- ``tests/test_report.py`` is your
target. Implement ``build_report`` until those tests pass, then implement
``save_report``.
"""

from pathlib import Path

# Severity ordering, highest first. Use these strings as your severity values
# so the report is consistent and sortable.
SEVERITY_ORDER = ("high", "medium", "low")


def build_report(domain, results):
    """Turn raw per-check results into a severity-ranked summary.

    Args:
        domain: The domain these results belong to, e.g. ``"example.com"``.
        results: A dict mapping check name -> that check's raw return dict, e.g.
            {
                "headers": {... output of check_headers ...},
                "tls": {... output of check_tls ...},
                "dns": {...},
                "security_txt": {...},
                "exposed_files": {...},
            }
            (See ``tests/test_report.py`` for concrete example input.)

    Returns:
        A dict summarizing findings. A suggested shape:
            {
                "domain": "example.com",
                "findings": [
                    {
                        "severity": "high",
                        "check": "exposed_files",
                        "title": "Exposed file: /.env",
                        "detail": "Returned HTTP 200",
                    },
                    {
                        "severity": "medium",
                        "check": "headers",
                        "title": "Missing header: Content-Security-Policy",
                        "detail": "...",
                    },
                    ...
                ],
                "counts": {"high": 1, "medium": 3, "low": 0},
            }
        ``findings`` should be sorted by severity using ``SEVERITY_ORDER``.

    TODO (implement this yourself):
        1. Walk each check's raw result and translate it into zero or more
           finding dicts. Decide your own severity mapping, for example:
             - exposed_files: any exposed path        -> high
             - tls: invalid cert / expired / expiring  -> high / medium
             - headers: each missing security header   -> medium (or low)
             - dns: missing SPF or DMARC               -> medium / low
             - security_txt: absent                    -> low (informational)
           The two tests that ship with the scaffold assert that (a) a missing
           security header produces a finding and (b) an exposed file produces
           a finding -- so make sure those two paths definitely emit findings.
        2. Be defensive: a check may have errored and its result may contain an
           ``"error"`` key instead of data. Don't crash on missing keys; use
           ``.get()``.
        3. Sort ``findings`` by severity (high -> low). ``SEVERITY_ORDER.index``
           makes a handy sort key.
        4. Tally ``counts`` per severity and return the report dict.
    """
    raise NotImplementedError("build_report: see TODO in this file")


def save_report(domain, report, directory, fmt):
    """Write a built report to disk as markdown or JSON.

    Args:
        domain: The domain the report is for (used in the filename).
        report: The dict returned by ``build_report``.
        directory: Destination directory (str or Path), e.g. ``"reports"``.
        fmt: Either ``"md"`` or ``"json"``.

    Returns:
        The ``pathlib.Path`` of the file that was written.

    TODO (implement this yourself):
        1. Ensure ``directory`` exists (``Path(directory).mkdir(parents=True,
           exist_ok=True)``).
        2. Build a safe filename, e.g. ``{domain}.{fmt}`` (sanitize the domain
           -- replace ``/`` and ``:`` etc. -- so weird input can't escape the
           directory). Consider adding a timestamp if you want history.
        3. For ``fmt == "json"``: ``json.dumps(report, indent=2)``.
           For ``fmt == "md"``: render a readable markdown document -- a title
           with the domain, the severity counts, then a section/table listing
           each finding. Group or order by severity.
        4. Write the file (UTF-8) and return its Path.
        5. Raise a clear ``ValueError`` for an unsupported ``fmt``.
    """
    raise NotImplementedError("save_report: see TODO in this file")
