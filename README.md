# DMARC Monitor

[![License](https://img.shields.io/badge/License-Proprietary-red?style=flat-square)](LICENSE)

Self-hosted DMARC monitoring for a service provider looking after other
people's domains. Collects aggregate, forensic and TLS reports, says in plain
English what is wrong with each domain, offers to fix the DNS, and produces a
report a customer can read.

Two pieces, sharing a SQLite file and nothing else:

- **`dmarc`** — a single self-contained binary. Collects reports, imports
  folders, plans and applies DNS changes, writes client reports. No .NET
  install needed, no checkout beside it. Runs on a schedule.
- **The web app** — the screens. Triage, per-domain evidence, the Fix
  worklist, reports. Reads what the CLI writes.

Neither needs the other running.

**Start here: [docs/RUNNING.md](docs/RUNNING.md).** It gets you from nothing to
a client report without a mailbox or an app registration.

---

## Documentation

| | |
|---|---|
| [docs/RUNNING.md](docs/RUNNING.md) | Day-to-day use. Read this first. |
| [docs/INGEST-SETUP.md](docs/INGEST-SETUP.md) | Pointing it at a mailbox: Entra app registration, permissions, the application access policy. |
| [docs/DEPLOYING.md](docs/DEPLOYING.md) | Putting it on a server: systemd, TLS, updates, MTA-STS hosting. |
| [docs/OPEN-ISSUES.md](docs/OPEN-ISSUES.md) | What is known to be unfinished. |

## What it monitors

**Report ingestion**
- DMARC aggregate (`rua`) — RFC 7489 XML, with override reasons and subdomain analysis
- DMARC forensic (`ruf`) — RFC 6591 MIME/ARF
- TLS-RPT — RFC 8460 JSON

**What it tells you**
- Every domain ranked by what needs doing, worst first — never an average,
  because an average across a book of domains hides the one that is broken
- Which sending sources are the customer's own, which are third parties
  signing as themselves, and which proved nothing at all
- Signatures that verified and were discarded anyway for not aligning — the
  line in a report that reads as a contradiction and is not
- Receivers that used to report on a domain and have stopped, which is how a
  clean-looking pass rate becomes "whoever is left"

**What it can change**
- SPF, DKIM and DMARC records through Cloudflare or Azure DNS, or as
  copy-and-paste instructions for any other provider
- Every change planned first, applied only on a click with a reason, verified
  afterwards, and reversible

**Transport security**
- MTA-STS policies, served by the web app itself at
  `mta-sts.<domain>/.well-known/mta-sts.txt`
- TLS-RPT records

## Requirements

- **Running it:** nothing. The CLI is self-contained; the web app ships as a
  published bundle. Linux or Windows.
- **Building it:** .NET 8 SDK.
- **Collecting from a mailbox:** a Microsoft 365 tenant and an Entra app
  registration — see [docs/INGEST-SETUP.md](docs/INGEST-SETUP.md). Not needed
  to try it: `dmarc import` reads a folder of reports.

## Building

```
dotnet build src/DmarcMonitor.sln
dotnet test  src/DmarcMonitor.sln
```

Releases publish the CLI for `win-x64`, `linux-x64` and `linux-arm64`, plus the
web bundle. See `.github/workflows/release.yml`.

---

## The PowerShell scripts

The `.ps1` files in this directory are the original Windows product: a WPF
desktop dashboard storing its configuration in the Windows Registry. It has
been **superseded by the .NET application above** and is kept only for
reference while anything still depends on it.

It is not what this repository releases and not what `deploy/` installs:
`release.yml` publishes the .NET CLI and web bundle, and `deploy/update.sh`
installs the web bundle. Nothing in `src/` or `deploy/` calls a `.ps1` file.

Its Pester tests still run in CI, so it is verified, not abandoned — but a new
installation should follow [docs/RUNNING.md](docs/RUNNING.md), not
`Install-DMARCMonitor.ps1`.

## License

Proprietary. See [LICENSE](LICENSE).
