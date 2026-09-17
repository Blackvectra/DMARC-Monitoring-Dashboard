# Open issues

What is known to be wrong or missing, where it lives, and how to fix it.
Ordered by what would embarrass us in front of a client first.

Everything here was found by importing 1,687 real reports across ten NRG
client domains on 17 September 2026. The fixture corpus never surfaced any of
it, which is the main lesson: **the bugs that matter are in what the product
says, not in whether it runs, and only real mail flows expose them.**

---

## 1. The export is missing months of reports

**Area** `tools/Export-DMARCAttachments.ps1`
**Severity** Blocks trusting any number the product reports.

Six of ten folders exported right up to the current day. Four stopped dead
part way through their history:

| domain | last report exported | gap |
|---|---|---|
| dunncountynd.gov | 2026-05-12 | 128 days |
| redriverrc.com | 2026-06-03 | 106 days |
| mortonnd.gov | 2026-07-17 | 62 days |
| mcleanelectric.com | nothing at all | — |

Morton is provably still reporting: reports dated 2026-09-14 to 09-16 were
supplied by hand from the same mailbox while the export contains nothing after
17 July. So this is the export losing data, not the monitoring stopping.

**Most likely cause, already fixed but unconfirmed.** `Attachment.FileName`
throws for some attachment kinds rather than returning empty. Under
`$ErrorActionPreference = 'Stop'` that ended the whole run part way through a
folder, and Outlook hands items back oldest-first, so a folder would keep its
early history and lose everything after the bad item. That is exactly the
shape of the four failures.

**How to confirm.** Re-run version `2026-09-17.4` or later, which prints its
version on startup and now accounts for every message it did not export:

```
DMARC_bmcedc.com                         2       90
    88 attachment(s) skipped, not a report type: .msg
```

Four causes produce four different lines, and each needs a different fix:
`.msg`/`.eml` means reports are forwarded and nested inside another message
and need extracting; "had no attachment at all" means cached-mode
header-only sync; "could not be read from Outlook" means MAPI is refusing
items; an unexpected extension is a one-line change to `$Extensions`.

**Until this is re-run, every figure in the product is computed on a partial
dataset.**

---

## 2. `TriageService` and `DomainDetailService` have no tests

**Area** `src/DmarcMonitor.Web/Data/`
**Severity** Medium. Both classify or rank, and neither is covered.

`CorrelationService` moved to `src/DmarcMonitor.Core/Intelligence/` and now has
seven tests, including one that fails against the exact regression that
cleared a genuine forger. The two services still in Web do not.

`DomainDetailService` carries the same three-bucket rule as the client report
(own sending path / third-party signing as itself / impersonation) and was
fixed at the same time, on inspection rather than on a failing test.
`TriageService` decides the order an operator reads the fleet in.

**How to fix.** Same move: both take `ReportStoreConnection`, which is a Web
type, and both would work against a database path exactly as
`CorrelationService` now does. Ranking and classification are domain logic and
belong in Core where they can be tested; the Web project keeps the pages.

## 3. The web app is read-only about its own configuration

**Area** `src/DmarcMonitor.Web/Components/Pages/Settings.razor`
**Severity** Low.

Every sidebar link now resolves: Triage, Domains, a domain, Clients, Import,
Sources, Reports, Settings. Reports previews a client's month and opens the
real document through the same renderer the CLI uses, so the two cannot drift.

Settings shows what the instance is configured to do but cannot change any of
it. That is deliberate for now - a form writing to appsettings.json becomes a
second source of truth that disagrees with the file after a restart - but the
provider name in particular is something an operator will want to set without
editing a file on the server.

**How to fix, when it is worth it.** A small writable configuration store
(a table in the existing database, read at startup with the file as the
default) rather than rewriting appsettings.json.

## 4. Local builds cannot reproduce CI's analyzer set

**Area** `src/Directory.Build.props`, `.github/workflows/`
**Severity** Medium. Costs a CI round trip per analyzer error.

`<AnalysisLevel>latest-recommended</AnalysisLevel>` resolves against whatever
SDK is present, and CI's SDK enforces rules this environment does not. CA1873
failed CI three times while `dotnet build -c Release` was clean locally, even
after installing CI's exact SDK version (8.0.425).

**How to fix.** Pin the analyzer package rather than inheriting it from the
SDK:

```xml
<PackageReference Include="Microsoft.CodeAnalysis.NetAnalyzers" Version="..." PrivateAssets="all" />
```

Note that 9.0.0 and 10.0.401 were both tried and neither reproduced CA1873, so
the rule is arriving from somewhere else — likely the
`Microsoft.Extensions.Logging` analyzers travelling with a transitive package
version that differs between here and CI. Worth a `packages.lock.json` so
both restore identically.

---

## 5. Corpus gaps

**Area** `src/DmarcMonitor.Core.Tests/Fixtures/`
**Severity** Medium. These are the report shapes we have never parsed.

- **No forensic/RUF reports at all.** The parser exists; nothing has exercised
  it against a real one.
- **No TLS reports with failures.** Every TLS fixture is a clean day, so the
  failure wording has never been seen.
- **No `<reason>` policy overrides.** Forwarders and mailing lists produce
  these constantly in the wild, and the code excludes overridden rows from
  intelligence on the assumption they are noise. That assumption is untested.
- **Receivers never seen:** Proofpoint, Barracuda, Fastmail, ProtonMail, Zoho,
  GoDaddy, Rackspace, and any non-Western provider.

**How to fix.** Collect from the re-run export (issue 1), which will have
roughly three more months of traffic, and add the unusual ones as fixtures.

---

## 6. Distribution

**Area** `src/DmarcMonitor.Cli/`, release tooling
**Severity** Medium. Nobody can run this without a git checkout and an SDK.

`dmarc.exe` now builds self-contained and carries the schema internally, so it
works on a bare machine:

```
dotnet publish src/DmarcMonitor.Cli -c Release -r win-x64 --self-contained \
  -p:PublishSingleFile=true -o out
```

**What is missing.** No release workflow produces that artifact, so there is
nothing to download. `e_sqlite3.dll` also lands beside the exe rather than
inside it — add `-p:IncludeNativeLibrariesForSelfExtract=true` and confirm
SQLite still loads, because that flag has broken native loading before.

The web app has no published form at all: no service definition, no
`appsettings` template, no note on where the database should live on a server.

---

## 7. Smaller things

| area | what | how |
|---|---|---|
| `ClientReportRenderer` | The `(s)` plural convention is everywhere — "1 service(s) you use is" — which is honest but reads as unfinished in a client-facing document | Pluralise properly for the common nouns; the `Was`/`Is` helpers in `ReportNarrative` already show the pattern |
| `ReportCommand` | `--provider` defaults to the literal string "your IT provider" | Either make it required, or read it from configuration so it is set once |
| `ClientReportRenderer` | The report's domain table does not mention `pct`, though the domain page does | Carry `Pct` through and say "on N% of mail", same wording as `DomainView` |
| `ClientCommand` | Prints "Added X as 'slug'" while the Clients page says "filed as" | Pick one phrasing |
| `ReportPeriod` | An explicit `--month` can select the current, incomplete month and the report does not say so | Say "covers 1–17 Sep, in progress" when the period has not ended |

---

## Fixed today, for reference

These were all live in front of a client and are all now covered by tests that
fail without the fix.

1. **A customer's own mail relay called a forger.** `35.174.145.124` rated High
   against seven of ten clients. It is a gateway carrying their outbound that
   breaks a share of its own signatures in transit. Fixed in three places; the
   rule is that passing even once *for that domain* is what a forger cannot do.
2. **The client report accusing the same relay.** DMV WRR's August report said
   177 messages were "sent by someone who is not you". It was their own mail.
3. **"210 of those 137."** The impersonation sentence reused a figure counting
   every failing message on every enforcing domain.
4. **Indicator counts disagreeing with their own lists.** "7 domain(s)" above a
   list of nine: the count was windowed, the names were not.
5. **"0 silent" while five domains had gone dark** for between 14 and 128 days.
   Silent counted only domains that had never reported, not ones that stopped.
