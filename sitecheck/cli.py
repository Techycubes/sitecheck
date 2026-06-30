"""Command-line entry point for sitecheck.

This file is pure plumbing: it parses arguments, runs each passive check
against each domain, hands the raw results to the report layer, and writes a
report to disk. It contains NO check logic itself -- that lives in
``sitecheck/checks/*`` and ``sitecheck/report.py``.

Checks are grouped into categories (``security`` and ``seo``). A subcommand
selects which category runs; the report groups findings by category.

Because the check/report functions are written to be defensive, every check is
wrapped so that an unimplemented (or failing) check is recorded as an error and
the run continues instead of crashing.

Usage:
    python -m sitecheck.cli example.com                 # security (default)
    python -m sitecheck.cli security example.com
    python -m sitecheck.cli seo example.com --format json
    python -m sitecheck.cli all example.com testphp.vulnweb.com
    python -m sitecheck.cli seo example.com --checks meta,robots_sitemap
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
    check_meta,
    check_robots_sitemap,
    check_indexability,
    check_social,
)
from . import report as report_mod

DEFAULT_USER_AGENT = f"sitecheck/{__version__} (+passive audit; read-only)"

# Maps a check's short name -> (callable, takes_user_agent?, category). The CLI
# uses this table to decide what to run, to honor --checks subsets, and to tag
# each result's category for the grouped report.
CHECKS = {
    # security
    "headers": (check_headers, True, "security"),
    "tls": (check_tls, False, "security"),
    "dns": (check_dns, False, "security"),
    "security_txt": (check_security_txt, True, "security"),
    "exposed_files": (check_exposed_files, True, "security"),
    # seo
    "meta": (check_meta, True, "seo"),
    "robots_sitemap": (check_robots_sitemap, True, "seo"),
    "indexability": (check_indexability, True, "seo"),
    "social": (check_social, True, "seo"),
}

# Subcommands -> the category of checks they run ("all" = every category).
COMMANDS = ("security", "seo", "all")
DEFAULT_COMMAND = "security"


def category_checks(command):
    """Return the ordered check names belonging to a command's category."""
    if command == "all":
        return list(CHECKS)
    return [name for name, (_f, _ua, cat) in CHECKS.items() if cat == command]


def _normalize_argv(argv):
    """Allow omitting the subcommand for backward compatibility.

    ``sitecheck example.com`` is rewritten to ``sitecheck security example.com``
    so existing invocations keep working. An explicit command, ``--version`` or
    ``--help`` is left untouched.
    """
    argv = list(argv)
    if not argv:
        return argv
    if argv[0] in COMMANDS or argv[0] in ("-h", "--help", "--version"):
        return argv
    return [DEFAULT_COMMAND, *argv]


def build_parser():
    """Construct the argument parser (top level + per-command subparsers)."""
    # Flags shared by every subcommand live on a parent parser.
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "domains",
        nargs="+",
        metavar="DOMAIN",
        help="One or more bare domains to check, e.g. example.com",
    )
    parent.add_argument(
        "--checks",
        default="all",
        help=(
            "Comma-separated subset of checks to run within the chosen "
            "category, or 'all' (default)."
        ),
    )
    parent.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to write reports into (default: reports).",
    )
    parent.add_argument(
        "--format",
        choices=("md", "json"),
        default="md",
        help="Report format: md or json (default: md).",
    )
    parent.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="User-Agent string to send with HTTP requests.",
    )

    parser = argparse.ArgumentParser(
        prog="sitecheck",
        description=(
            "Passive, non-intrusive audits for domains you own or have "
            "permission to test. Read-only checks only -- no port scanning, "
            "no exploitation, no automated submission, no site crawling."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"sitecheck {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", metavar="{security,seo,all}")
    subparsers.add_parser(
        "security", parents=[parent], help="Run the security checks (default)."
    )
    subparsers.add_parser(
        "seo", parents=[parent], help="Run the SEO checks."
    )
    subparsers.add_parser(
        "all", parents=[parent], help="Run every check (security + SEO)."
    )
    parser.set_defaults(command=DEFAULT_COMMAND)
    return parser


def parse_args(argv=None):
    """Parse ``argv`` (defaults to sys.argv), applying the default subcommand."""
    if argv is None:
        argv = sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(_normalize_argv(argv))
    if not getattr(args, "domains", None):
        parser.error("at least one DOMAIN is required")
    return args


def selected_checks(spec, command):
    """Resolve a --checks spec into an ordered list of check names.

    The spec is applied within the chosen command's category. Raises
    ValueError on an unknown check (or one outside the category).
    """
    available = category_checks(command)
    if spec.strip().lower() == "all":
        return available
    names = [n.strip() for n in spec.split(",") if n.strip()]
    unknown = [n for n in names if n not in available]
    if unknown:
        raise ValueError(
            f"Unknown check(s) for '{command}': {', '.join(unknown)}. "
            f"Valid checks: {', '.join(available)}."
        )
    return names


def run_check(name, domain, user_agent):
    """Run a single named check, capturing NotImplementedError and failures.

    Returns the check's raw result dict, or a ``{"error": ...}`` dict if the
    check is not implemented yet or raised, so one check never aborts the run.
    """
    func, takes_ua, _category = CHECKS[name]
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
        checks = selected_checks(args.checks, args.command)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        f"sitecheck ({args.command}): passive checks only. Only scan domains "
        "you own or have permission to test.\n"
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
