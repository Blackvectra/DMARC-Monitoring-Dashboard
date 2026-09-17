# Open issues

What is known to be wrong or missing, where it lives, and how to fix it.
Ordered by what would embarrass us in front of a client first.

Everything here was found by importing 1,687 real reports across ten NRG
client domains on 17 September 2026. The fixture corpus never surfaced any of
it, which is the main lesson: **the bugs that matter are in what the product
says, not in whether it runs, and only real mail flows expose them.**

---

## 1. Ingest has never been run against a real mailbox

**Area** `src/DmarcMonitor.Core/Graph/`, `src/DmarcMonitor.Cli/Commands/IngestCommand.cs`
**Severity** High. It is the whole collection path in production and no line of
it has touched Exchange.

`dmarc ingest` reads the shared mailbox through Microsoft Graph: it walks the
child folders a mail rule sorts reports into, carries the folder name through
for attribution, stores what it parses, and moves each message out so it is
not read twice. `GraphMailboxClient`, `GraphThrottleHandler` and the
move-after-handover ordering are all unit tested against a fake mailbox and
have never spoken to a real one.

Untested against reality, in rough order of how likely they are to bite:

- **Throttling.** Graph returns 429 with `Retry-After` under load. The handler
  honours it in tests; a mailbox with thousands of messages is where that gets
  exercised for the first time.
- **Folder names with a backslash.** The live mailbox has folders literally
  named `DMARC\bmcedc.com`. Graph addresses folders by id, so this should be
  irrelevant, but nothing has proved it.
- **The move.** A message is filed only after its reports are stored, so a
  crash re-reads rather than loses. The duplicate check should make the second
  read harmless. Untested outside the fake.
- **Attachment size and shape.** Large or unusual attachments come back
  differently from Graph than the fake produces.

**How to fix.** An app registration in the tenant with `Mail.ReadWrite` as an
*application* permission, admin consent, a certificate, and an application
access policy restricting it to the one shared mailbox so it cannot read
anything else. Then `--dry-run` first: it parses and reports without writing
or moving anything, so the first run against a live mailbox is safe.

---

## 1a. The Outlook exporter is a stopgap, not the collection path

**Area** `tools/Export-DMARCAttachments.ps1`
**Severity** Low, now that its role is clear.

It exists to get a pile of reports off a desktop without an app registration,
which is how the 1,687-report dataset reached testing. It is not how the
product collects mail and never was, so its bugs do not block anything the
product does.

It did truncate four folders in the live export — two months for
`mortonnd.gov`, three for `redriverrc.com`, everything for
`mcleanelectric.com` — almost certainly because `Attachment.FileName` throws
for some attachment kinds and, under `$ErrorActionPreference = 'Stop'`, ended
the run part way through a folder. Outlook hands items back oldest-first,
which is why each affected folder kept its early history and lost the rest.
That is fixed in version `2026-09-17.4`, and the script now accounts for every
message it did not export, but confirming it only matters if somebody needs
the export path again.

**What this does mean:** the ten-domain dataset used for testing is partial, so
figures quoted from it are lower bounds. Ingest against the live mailbox would
collect the lot.

---

## 2. Nothing checks the pages themselves

**Area** `src/DmarcMonitor.Web/Components/Pages/`
**Severity** Low-to-medium. The logic behind the pages is covered; the markup
is not.

All three source classifiers and both fleet views now live in Core with tests:
`CorrelationService`, `TriageService`, `DomainDetailService`, plus the report
builder, the narrative and the renderer. Between them they cover every
judgement the product makes about a sending source.

What is left uncovered is the Razor: a renamed property, a broken `@bind`, or
a page that throws on an empty database would all compile and all pass the
suite. They were caught today by driving the app with curl and Playwright by
hand, which does not survive into next week.

**How to fix.** A small `bunit` project over the pages, or a handful of
Playwright checks that load each route against a seeded database and assert on
one sentence. The route list is short enough to be worth doing exhaustively:
`/`, `/domains`, `/domains/{name}`, `/clients`, `/import`, `/sources`,
`/reports`, `/settings`.

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

## 6. Nothing has been released yet

**Area** `.github/workflows/release.yml`
**Severity** Low, now that the workflow exists but has never run.

`dmarc` publishes as a genuinely single file - schema compiled in, SQLite's
native library bundled rather than sitting beside it - and the workflow proves
it on every build by copying the binary into an empty directory and making it
create a database there. That check is the point: a missing embedded schema or
an unbundled native library both look fine until somebody copies the exe
somewhere on its own, which is the first thing anybody does.

Both the Windows and Linux jobs, and the web bundle, are untried: the workflow
has not been triggered. Tag a version or run it manually and see.

The web app is not self-contained and needs the ASP.NET Core 8 runtime on the
host. That is a deliberate trade - a self-contained web bundle is several
hundred megabytes - but it means "copy one file and run it" is true of the CLI
and not of the app.

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
