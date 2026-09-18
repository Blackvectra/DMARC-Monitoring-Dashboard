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
**Severity** Medium. This was rated Low until the gap it describes hid a bug
that made a whole page unusable. See below.

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

**What it cost.** The Fix page shipped with `@bind` pointing at a dictionary
indexer (`_reasons[key]`). Binding reads before anything writes, the key is
absent, and `KeyNotFoundException` is thrown *during render* - which kills the
circuit. The page then sits showing "Checking what it publishes…" forever,
with no error anywhere a user can see. Every page test passed throughout,
because a plain HTTP GET renders the page statically: `OnAfterRenderAsync`
never runs, the domains never load, and the offending control is never
rendered. It took driving a real browser to see it, and then it was obvious
in the server log.

Three controls had the same fault. All three now read through a helper that
defaults, and the missing key is the normal case rather than an exception.

**How to fix, when it is worth it.** Playwright against a seeded instance, in
CI. There is a working harness for it now - it is what found the bug above -
but it lives in a scratch directory rather than in the repository, so nothing
runs it on a pull request. Moving it in needs a seeded instance CI can start
and a way to stub DNS, since the pages that matter here are the ones that read
it.

## 3. The web app is read-only about its own configuration

**Area** `src/DmarcMonitor.Web/Components/Pages/Settings.razor`
**Severity** Low.

Every sidebar link now resolves: Triage, Domains, a domain, Clients, Import,
Sources, Reports, Settings. Reports previews a client's month and opens the
real document through the same renderer the CLI uses, so the two cannot drift.

Settings shows what the instance is configured to do and, apart from DNS
providers, cannot change any of it. That is deliberate for now - a form
writing to appsettings.json becomes a second source of truth that disagrees
with the file after a restart - but the provider name in particular is
something an operator will want to set without editing a file on the server.

DNS providers are the exception because they were never file configuration:
they live in `dns_provider_configs` with the token in the secret store, and
the page writes them the same way `dmarc dns set` does.

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

## 5. The DNS check is weaker without a database than it needs to be

**Area** `src/DmarcMonitor.Core/Dns/DnsLookup.cs`
**Severity** Low, and it undercuts the use it was built for.

`dmarc check --domain x` with no database is meant to answer "what is wrong
with this prospect's email setup" before they are a customer. Two of its
findings cannot fire in that mode:

- **MTA-STS mode** was read only from TLS reports. Fixed: `MtaStsFetcher`
  fetches the policy file the way a sender does, so the mode is known for any
  domain, prospect or customer, with or without reports. The paragraph below
  describes how it used to be.
- **(was) MTA-STS mode** comes from TLS reports, so a prospect's policy shows as
  published and never as *testing*, which is the interesting state. The mode is
  also in the policy file at
  `https://mta-sts.<domain>/.well-known/mta-sts.txt`, which is one HTTPS GET
  and would make this work standalone.
- **Unused includes** need observed sending, so there is nothing to match
  against. That one is unavoidable and correct: with no evidence the honest
  answer is silence.

Checked against nrgtechservices.com, which has MTA-STS in testing mode: with
`--db` the check reports it, without `--db` it says "nothing to change".

**How to fix.** Fetch the policy file when there is no observed mode, and treat
a fetch failure as unknown rather than absent - the same rule the DNS lookups
already follow.

---

## 6. Data parsed and stored, then never used

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

## 7. Nothing has been released yet

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

## 9. Uploads are bounded by numbers picked, not measured

**Area** `ReportAttachment`, `ImportUiService`
**Severity** Low.

Dropping files in the browser works, and was proven on the real thing: the
1,687-report export imports through the page in one go. The bounds it runs
under are reasoned rather than measured, though:

- 100 MB per uploaded file, because the file is read into memory whole before
  it is unpacked. The real export is 1.9 MB, so there is a lot of headroom,
  but a year of collection for thirty domains has not been tried.
- 25,000 archive members and 2 GB decompressed per file. Extraction is lazy,
  so memory holds one report at a time; these bound time and disk, not memory.
- 5,000 files in one drop.

An operator who exceeds any of them is told which one and what to do instead,
so the failure is legible. What has not been established is where the real
limits are: at what size the upload gets slow enough that the folder import
is the better answer.

## 10. The update path has never been run on a server

**Area** `deploy/update.sh`, `deploy/rollback.sh`
**Severity** Medium.

The release channel half is tested and was driven against the real GitHub API:
the Settings page reports what it is running and correctly says nothing has
been released yet. The scripts that install a release are not. They parse, and
their logic is legible, and neither has stopped and restarted a real service.

Two things about them worth knowing before the first run:

- **The rollback is not symmetric.** Putting the application back always
  works; the database is left alone unless `--database` is passed, because a
  migration that ran is still applied and the current database holds
  everything collected since the update. Getting this wrong in either
  direction loses something.
- **`appsettings.Production.json` lives in the application directory** and is
  not part of a release, so `update.sh` copies it across. If that copy ever
  fails silently the new install comes up with no database path, no tenant and
  no sign-in - which the health check would catch, but by rolling back rather
  than by saying what happened.

Try it first on a box with nothing real on it, between two tags that differ
only trivially.

## 10a. No ARM build, and no deployment has happened

**Area** `.github/workflows/release.yml`, `docs/DEPLOYING.md`
**Severity** Low.

**ARM: done.** The release now publishes `linux-arm64` too, verified locally
to be a 36 MB self-contained `ARM aarch64` executable. It is the one build
whose smoke test cannot run it - an x64 runner cannot execute an ARM binary -
so CI checks the architecture and the size instead and says so. That is
genuinely weaker than the x64 and Windows checks, which make the binary
create a database and read a report.

`DEPLOYING.md` itself is assembled from how the pieces are built rather than
from a deployment that happened. The proxy handling under it is covered by
tests - including the one that matters, that an unauthenticated instance
refuses a proxied request - but the systemd units, the Caddyfile and the Entra
app registration have not been run. The doc says so in its own last section.

## 11. The apply path has never written to a real zone

**Area** `src/DmarcMonitor.Core/Remediation/`, `dmarc fix`, the Fix page
**Severity** Medium. This is the feature the product exists for, and its
last step is untried.

Everything up to the provider is exercised against real data: `dmarc fix
--all` on the 1,687-report database plans the two `sp=none` removals
(bmcedc.com, ndunited.org), plans mortonnd.gov's move to quarantine, and
refuses its move to reject. The guardrails - refuse unsafe, no-op twice,
snapshot before writing, refuse a stale plan, roll back from the snapshot,
refuse a second rollback - are proven against the in-memory zone.

What has not happened is a write to Cloudflare or Azure DNS. Both providers
are tested against recorded responses whose shape comes from the API
documentation and the prototype, not from a call. Three things could be
wrong in ways the tests cannot see:

- **Cloudflare TXT quoting.** The API returns content quoted and accepts it
  either way; the provider unquotes on read and sends unquoted. If a zone
  turns out to hold content with the quotes as part of the value, the
  snapshot comparison in `ApplyAsync` will call the plan stale and refuse,
  which is the safe failure.
- **Azure record-set replacement.** The provider reads the set, swaps one
  value and PUTs the whole set back so the other TXT values at the apex
  survive. A PUT that Azure treats as a partial update, or a set with an
  `etag` requirement, would show up here first.
- **Propagation.** `VerifyAsync` resolves through its own uncached client,
  but it resolves through whatever resolver the host uses. A resolver that
  itself caches for the old TTL will say "not yet" for that long, and the
  history table will say "accepted, not yet seen in DNS" until then.

**How to try it.** One domain, with a Cloudflare token scoped to that zone
only:

    dmarc dns set --client <slug> --domain <d> --provider cloudflare --zone-id <id>
    dmarc dns test --domain <d>
    dmarc fix --domain <d>                       # dry run: shows before and after
    dmarc fix --domain <d> --apply --reason "..."
    dmarc fix --history
    dmarc fix --rollback <id> --reason "trying the rollback"

Then look at the zone in the provider's own UI after each step. The Fix page
does the same with buttons.

Not built, and known: SPF flattening, DKIM publication, MTA-STS and TLS-RPT
records, and BIMI. The `dns_change_plans` CHECK constraint already admits
them. Removing an include on the strength of "no mail seen from it" is
deliberately not plannable and should stay that way.

## 8. Smaller things

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
