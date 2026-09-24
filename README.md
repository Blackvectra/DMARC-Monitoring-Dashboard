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

## Just want to look at it?

Download **`DMARC-Monitor-Windows.zip`** from the latest release, unzip it, and
double-click **`Start DMARC Monitor.cmd`**. The dashboard opens in your
browser.

Two things Windows will do on the way, neither of which means anything is
wrong. Right-click the .zip → Properties → tick **Unblock** *before*
extracting, which saves clearing the download mark from five hundred files
one at a time. And SmartScreen will say "Windows protected your PC", because
these binaries are not signed yet — *More info*, then *Run anyway*.
`SHA256SUMS.txt` on the release page is there if you would rather check the
file than trust it. See [docs/SIGNING.md](docs/SIGNING.md).

Do not download `dmarc-web.zip` for this. That is the Linux server bundle and
it contains no Windows executable at all. `dmarc.exe` is the command-line
tool, not the dashboard; double-clicked, it prints its help and exits.

No .NET install, no administrator, no service, no reverse proxy, no Entra app
registration, no server. It creates its own database in the folder it is run
from, serves that machine and nothing else, and deleting the folder removes
every trace. Drop report files onto the Import page — or point the `dmarc.exe`
beside it at a directory of them:

```
dmarc.exe import --from "C:\reports"
```

It is the same application a deployment runs, in the local trial mode it
already had, so what you are looking at is the product rather than a demo of
it. CI publishes that zip, runs the executable in an empty folder with the
.NET toolchain removed from `PATH`, and checks the dashboard renders — on
every push.

**Then: [docs/RUNNING.md](docs/RUNNING.md).** It gets you from nothing to a
client report without a mailbox or an app registration.

---

## Documentation

| | |
|---|---|
| [docs/RUNNING.md](docs/RUNNING.md) | Day-to-day use. Read this first. |
| [docs/INGEST-SETUP.md](docs/INGEST-SETUP.md) | Pointing it at a mailbox: Entra app registration, permissions, the application access policy. |
| [docs/DEPLOYING.md](docs/DEPLOYING.md) | Putting it on a server: systemd, TLS, updates, MTA-STS hosting. |
| [docs/AWS.md](docs/AWS.md) | One EC2 instance, start to finish, reachable from work, home and a phone — with Entra sign-in, MFA and passkeys. |
| [docs/FEATURE-MATRIX.md](docs/FEATURE-MATRIX.md) | What this has against what DMARC platforms generally have, and what it deliberately does not. |
| [docs/COMPARISON.md](docs/COMPARISON.md) | Why not just run parsedmarc and OpenSearch. Where each wins, and how to run both. |
| [docs/DATA-HANDLING.md](docs/DATA-HANDLING.md) | What it holds, where it lives, how long, and who can see it. Written to hand to a client who asks. |
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
  published bundle. Linux or Windows. On a server, one command sets up
  Ubuntu, Amazon Linux or Windows from nothing - `deploy/bootstrap.sh` or
  `deploy/bootstrap.ps1` - see [docs/DEPLOYING.md](docs/DEPLOYING.md).
- **Building it:** .NET 8 SDK.
- **Collecting from a mailbox:** a Microsoft 365 tenant and an Entra app
  registration — see [docs/INGEST-SETUP.md](docs/INGEST-SETUP.md). Not needed
  to try it: `dmarc import` reads a folder of reports.

## Building

```
dotnet build src/DmarcMonitor.sln
dotnet test  src/DmarcMonitor.sln
```

Releases publish the CLI for `win-x64`, `linux-x64` and `linux-arm64` — each
built and executed on the architecture it targets — plus the web bundle for a
server and the self-contained Windows trial zip. See
`.github/workflows/release.yml`.

Releases fire on a **tag**, not on a merge: `git tag v1.2.3 && git push origin
v1.2.3`. Merging to `main` builds nothing installable, and `bootstrap.sh`
downloads the latest release, so an install run straight after a merge quietly
gets the previous tag's build.

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
  repository, no .NET, no app registration. Marks each message read once its
  report is saved (`-LeaveUnread` to skip). Its tests are in `tests/` and run
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
