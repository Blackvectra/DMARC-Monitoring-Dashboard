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

## 2. The pages are checked, the browser is not

**Area** `src/DmarcMonitor.Web.Tests/`
**Severity** Low.

Every route now loads in a test: the real application in process, over real
HTTP, through the real authentication pipeline, against a seeded database.
They assert one sentence per page, so they fail when a page breaks and stay
quiet when it is restyled. Twenty-eight of them, and reinstating the triage
silence turns two red.

What they do not exercise is anything needing a browser: the interactive half
of Blazor. Pressing Import, choosing a client from the dropdown, and typing a
name into the client form all go through a SignalR circuit these tests never
open. The services behind each of those are covered in Core, so what is
untested is the wiring between the control and the handler.

**How to fix, when it is worth it.** Playwright against a seeded instance,
driving the three forms. The handlers are already tested, so this only needs
to prove the buttons reach them.

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

## 5. Data parsed and stored, then never used

**Area** `src/DmarcMonitor.Core/Aggregate/`, `src/DmarcMonitor.Core/Storage/`
**Severity** Low. Nothing is wrong; something useful is sitting unused.

`envelope_from` is parsed, stored on every record, and never read back out.
On the live corpus 14,937 of 20,465 records carry one, and it is what makes a
sender identifiable:

| envelope_from | what it is |
|---|---|
| `bounce.myngp.com` | NGP VAN, 7,889 messages for one client |
| `em318306.nrgtechservices.com` | SendGrid |
| `psm.knowbe4.com` | KnowBe4 security-awareness training |

"Signed as `training.knowbe4.com`" is harder to act on than "bounces to
`psm.knowbe4.com`", and the report currently shows only the former.

**How to fix.** Carry it onto `ReportSource` from the failing rows, the same
way `AuthenticatedFor` is, and show it beside "signed as" in the table of the
client's own mail that is at risk.

One value needs handling first: 933 messages carry an `envelope_from` of
`<>`, the null return path used for bounces and delivery notifications. It
survives `NormaliseDomain` unchanged and would render literally. Dormant while
nothing reads the field; visible the moment something does.

`discovery_method` and `testing` arrive in DMARCbis reports and are ignored.
Neither is worth storing yet.

### Corpus gaps, revisited

The earlier version of this section guessed. Measured against all 1,687
reports:

- **Policy overrides: present after all.** 40 of them, 23 `forwarded` and 17
  `local_policy`. The claim that there were none was wrong, and finding them
  is what exposed the totals-versus-tables gap.
- **TLS reports: 35, all MTA-STS, no failures.** The guess was right. The
  useful part turned out to be the mode rather than the failures: two domains
  publish in `testing`, which the report now says.
- **DMARCbis: already arriving.** Four reports use the
  `urn:ietf:params:xml:ns:dmarc-2.0` namespace and parse correctly.
- **Still absent:** forensic/RUF reports, any TLS failure, and receivers
  outside the eight seen (Proofpoint, Barracuda, Fastmail, ProtonMail, Zoho,
  GoDaddy, Rackspace, non-Western providers).

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
