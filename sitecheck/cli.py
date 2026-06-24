"""Command-line entry point for sitecheck.

This file is pure plumbing: it parses arguments, runs each passive check
against each domain, hands the raw results to the report layer, and writes a
report to disk. It contains NO security-check logic itself -- that lives in
``sitecheck/checks/*`` and ``sitecheck/report.py``, which you implement.

Because the check/report functions are still stubs that raise
NotImplementedError, this CLI is written defensively: every check is wrapped so
that an unimplemented (or failing) check is recorded as an error and the run
continues instead of crashing.

Usage:
    python -m sitecheck.cli example.com
    python -m sitecheck.cli example.com testphp.vulnweb.com --format json
    python -m sitecheck.cli example.com --checks headers,tls --output-dir out
"""

import argparse
import sys

from . import __version__
from .checks import (
    check_headers,
    check_tls,
    check_dns,
    check_security_txt,
    check_exposed_files,
)
from . import report as report_mod

DEFAULT_USER_AGENT = f"sitecheck/{__version__} (+passive security audit; read-only)"

# Maps a check's short name -> (callable, takes_user_agent?). The CLI uses this
# table both to decide what to run and to let --checks select a subset.
CHECKS = {
    "headers": (check_headers, True),
    "tls": (check_tls, False),
    "dns": (check_dns, False),
    "security_txt": (check_security_txt, True),
    "exposed_files": (check_exposed_files, True),
}


def parse_args(argv=None):
    """Build the argument parser and parse ``argv`` (defaults to sys.argv)."""
    parser = argparse.ArgumentParser(
        prog="sitecheck",
        description=(
            "Passive, non-intrusive security audit for domains you own or "
            "have permission to test. Read-only checks only -- no port "
            "scanning, no exploitation, no automated contact submission."
        ),
    )
    parser.add_argument(
        "domains",
        nargs="+",
        metavar="DOMAIN",
        help="One or more bare domains to check, e.g. example.com",
    )
    parser.add_argument(
        "--checks",
        default="all",
        help=(
            "Comma-separated subset of checks to run "
            f"({', '.join(CHECKS)}), or 'all' (default)."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to write reports into (default: reports).",
    )
    parser.add_argument(
        "--format",
        choices=("md", "json"),
        default="md",
        help="Report format: md or json (default: md).",
    )
    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="User-Agent string to send with HTTP requests.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"sitecheck {__version__}",
    )
    return parser.parse_args(argv)


def selected_checks(spec):
    """Resolve a --checks spec string into an ordered list of check names.

    Raises SystemExit (via the caller) on an unknown check name.
    """
    if spec.strip().lower() == "all":
        return list(CHECKS)
    names = [n.strip() for n in spec.split(",") if n.strip()]
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        raise ValueError(
            f"Unknown check(s): {', '.join(unknown)}. "
            f"Valid checks: {', '.join(CHECKS)}."
        )
    return names


def run_check(name, domain, user_agent):
    """Run a single named check, capturing NotImplementedError and failures.

    Returns the check's raw result dict, or a ``{"error": ...}`` dict if the
    check is not implemented yet or raised. This is what keeps the CLI usable
    while the check bodies are still stubs.
    """
    func, takes_ua = CHECKS[name]
    try:
        if takes_ua:
            return func(domain, user_agent)
        return func(domain)
    except NotImplementedError:
        return {"error": "not implemented yet", "_stub": True}
    except Exception as exc:  # noqa: BLE001 - CLI must not crash on one check
        return {"error": f"{type(exc).__name__}: {exc}"}


def run_domain(domain, checks, user_agent):
    """Run all selected checks against one domain; return a results dict."""
    results = {}
    for name in checks:
        print(f"  [{name}] ...", end="", flush=True)
        result = run_check(name, domain, user_agent)
        status = "stub" if result.get("_stub") else (
            "error" if result.get("error") else "ok"
        )
        print(f" {status}")
        results[name] = result
    return results


def main(argv=None):
    """Program entry point. Returns a process exit code."""
    args = parse_args(argv)

    try:
        checks = selected_checks(args.checks)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        "sitecheck: passive checks only. Only scan domains you own or have "
        "permission to test.\n"
    )

    exit_code = 0
    for domain in args.domains:
        print(f"Checking {domain}")
        results = run_domain(domain, checks, args.user_agent)

        try:
            report = report_mod.build_report(domain, results)
            path = report_mod.save_report(
                domain, report, args.output_dir, args.format
            )
            print(f"  report -> {path}")
        except NotImplementedError:
            # report.py is still a stub -- don't fail the run, just say so.
            print(
                "  report: build_report/save_report not implemented yet "
                "(implement sitecheck/report.py)"
            )
            exit_code = 1
        except Exception as exc:  # noqa: BLE001
            print(f"  report: error: {type(exc).__name__}: {exc}", file=sys.stderr)
            exit_code = 1
        print()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
