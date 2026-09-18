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
  published bundle. Linux or Windows. On a server, `deploy/install.sh` sets
  up Ubuntu or Amazon Linux from the release files - see
  [docs/DEPLOYING.md](docs/DEPLOYING.md).
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

## The PowerShell

Two operator tools and one leftover. The original Windows product — a WPF
dashboard, its report engine, DNS remediation, client reporting and the rest —
has been removed: every part of it is **superseded by the .NET application
above**, which is tested and audited where the PowerShell copies were not.

**`tools/`** holds the two scripts worth keeping, because nothing in .NET does
what they do:

- **`Export-DMARCAttachments.ps1`** — one file to copy onto a machine with
  Outlook open when there is no other way to get the reports out. No
  repository, no .NET, no app registration. Its tests are in `tests/` and run
  in CI.
- **`Test-DMARCMailRules.ps1`** — a read-only check of the inbox rules that
  file reports into per-domain folders: which are switched off, which Exchange
  has marked as failing, which domains have no rule, and how close the mailbox
  is to its 256 KB rules quota — the one that looks exactly like "the rule I
  just made does not work". Needs the ExchangeOnlineManagement module.

**`legacy/Install-DMARCMonitor.ps1`** is the one file left from the old
product. Most of it set up the Windows dashboard and is dead; the part that is
not creates the Entra app registration, uploads the certificate, and applies
the application access policy that restricts `Mail.ReadWrite` to the one
mailbox — steps [docs/INGEST-SETUP.md](docs/INGEST-SETUP.md) describes by
hand. It is kept until that part is either extracted into `tools/` or judged
unnecessary. A new installation should follow
[docs/RUNNING.md](docs/RUNNING.md), not `Install-DMARCMonitor.ps1`.

## License

Proprietary. See [LICENSE](LICENSE).
