# sitecheck

A small, **passive** security & SEO auditor for websites. Point it at a
domain you own (or are authorized to test) and it reports on a handful of
low-impact, read-only signals, grouped into two categories.

**Security checks:**

- **Security headers** — HSTS, CSP, X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Permissions-Policy.
- **TLS certificate** — validity, days until expiry, negotiated protocol.
- **Email auth DNS** — presence of SPF and DMARC records.
- **security.txt** — whether the site publishes one (RFC 9116) and who its
  security contacts are.
- **Exposed files** — a HEAD request to a small fixed list of well-known
  sensitive paths (e.g. `/.env`, `/.git/config`) to flag any served with a 200.

**SEO checks:**

- **Meta** — presence and length of the `<title>` and meta description.
- **robots.txt & sitemap** — whether they exist, whether robots blocks all
  crawlers, whether a sitemap is declared.
- **Indexability** — `noindex` (meta or `X-Robots-Tag`), canonical URL,
  `<html lang>`, and viewport meta.
- **Social & structured data** — Open Graph, Twitter Card, and JSON-LD.

Results are turned into a severity-ranked (high / medium / low) report,
grouped by category, written to `reports/` as Markdown or JSON.

> This is a personal learning project. The scanning logic in `sitecheck/checks/`
> and `sitecheck/report.py` ships as documented stubs to be implemented.

## What this tool deliberately does NOT do

sitecheck is intentionally narrow and non-intrusive. It will never:

- **Port scan.** No connecting to anything beyond the normal web (443/80) and
  DNS lookups.
- **Exploit anything.** Finding a missing header or an exposed file means
  *reporting* it — never probing further, downloading the file, or attempting
  to use it.
- **Fuzz or brute-force.** The exposed-files check is a tiny *fixed* list, not a
  wordlist. It is not a directory buster.
- **Submit anything through contact forms, anywhere.** It does not fill in or
  POST to any form.
- **Auto-send disclosures.** If a `security.txt` is found, the most the tool
  will ever do is **draft** a disclosure note into an `outbox/` folder for *you*
  to read and send manually. It never emails or messages a contact itself.
- **Crawl the site (SEO).** The SEO checks fetch only a single page (the
  homepage) plus `/robots.txt` and `/sitemap.xml`. No spidering, no rank
  tracking, no keyword research, no third-party APIs, no headless browser.

In short: it only reads what a site already makes publicly available, and writes
its findings to your disk.

## Setup

Requires Python 3.9+.

```bash
# from the repo root
python -m venv venv

# activate it
source venv/bin/activate        # macOS / Linux
venv\Scripts\activate           # Windows (cmd)
venv\Scripts\Activate.ps1       # Windows (PowerShell)

pip install -r requirements.txt
pip install pytest              # only needed to run the tests
```

## Usage

The CLI has three subcommands — `security`, `seo`, and `all` — that select
which category of checks to run. If you omit the subcommand it defaults to
`security` (so older invocations keep working).

```bash
# security checks (default) — writes reports/<domain>.md
python -m sitecheck.cli example.com
python -m sitecheck.cli security example.com

# SEO checks
python -m sitecheck.cli seo example.com

# everything, as JSON, into a custom directory
python -m sitecheck.cli all example.com testphp.vulnweb.com \
    --format json --output-dir reports

# run only a subset within a category
python -m sitecheck.cli security example.com --checks headers,tls
python -m sitecheck.cli seo example.com --checks meta,robots_sitemap
```

Security checks: `headers`, `tls`, `dns`, `security_txt`, `exposed_files`.
SEO checks: `meta`, `robots_sitemap`, `indexability`, `social`.
`--checks all` (the default) runs every check in the chosen category.

Until the check/report stubs are implemented, the CLI still runs end to end —
each unimplemented check is reported as a stub and the run continues.

## Running the tests

```bash
pytest
```

`tests/test_report.py` ships with fake input data and asserts that
`build_report` flags a missing header and an exposed file. Use it as the target
while implementing `sitecheck/report.py`.

## ⚠️ Authorization

**Only scan domains you own or have explicit permission to test.** Unauthorized
scanning — even passive scanning — may violate a site's terms of service or your
local law. When you just want something to practice against, use an intentionally
vulnerable target such as [`testphp.vulnweb.com`](http://testphp.vulnweb.com)
(provided by Acunetix for testing).

## License

MIT — see [LICENSE](LICENSE).
