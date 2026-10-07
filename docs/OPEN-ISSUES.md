# Open issues

What is known to be wrong or missing, where it lives, and how to fix it.
Ordered by what would embarrass us in front of a client first.

Everything here was found by importing 1,687 real reports across ten NRG
client domains on 17 September 2026. The fixture corpus never surfaced any of
it, which is the main lesson: **the bugs that matter are in what the product
says, not in whether it runs, and only real mail flows expose them.**

---

## Fixed since this was written

Six, all found by looking at real screens with real data rather than by the
test suite — every one of them the product stating something it had not
established.

| | what it did | what it does now |
|---|---|---|
| **10c** | a new release opened empty, and a database carried across failed page by page | migrates itself in local trial mode, says what to run everywhere else |
| **Security score** | "10 of the 10 points lost to domains not requiring TLS" on an install that had never read DNS, while two of those domains served `enforce` | transport is scored only where DNS has been read, and the score says when it is not counting it |
| **TLS reports** | printed the mode senders had CACHED as the mode in force, so a domain serving `enforce` appeared under "in testing mode, which protects nothing" | an unverified mode is labelled as what senders had, drawn in no colour, and never counted into the warning |
| **Fix page** | offered a CNAME pointing a domain's MTA-STS at this app, under "No policy has been created yet", for a domain already serving `enforce` — following it would have replaced a working policy with a testing one | a domain serving its own reachable policy is recognised as such; nothing is offered and the page says what is already there |
| **Client report** | the failure causes double-counted a message that passed both checks without aligning: 9 + 6 + 94 where the truth was 4 + 1 + 5 + 94 | the four causes are mutually exclusive, and "both checks passed, neither aligned" is its own row |
| **Any mistyped URL** | 404 with a zero-byte body: a white page with no layout and no way back | the not-found page, with the layout around it |

The last one had middleware in place that did nothing: with no explicit
`UseRouting()` the framework inserts routing at the top of the pipeline, so by
the time a 404 came back up, routing had already happened and re-executing only
changed the path. Nothing routed it again.

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
  named `DMARC\client-a.example`. Graph addresses folders by id, so this should be
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
`acme.example`, three for `client-e.example`, everything for
`client-f.example` — almost certainly because `Attachment.FileName` throws
for some attachment kinds and, under `$ErrorActionPreference = 'Stop'`, ended
the run part way through a folder. Outlook hands items back oldest-first,
which is why each affected folder kept its early history and lost the rest.
That is fixed in version `2026-09-17.4`, and the script now accounts for every
message it did not export, but confirming it only matters if somebody needs
the export path again.

**What this does mean:** the ten-domain dataset used for testing is partial, so
figures quoted from it are lower bounds. Ingest against the live mailbox would
collect the lot.

**`-MoveToDeleted`, and a mark-read failure nobody could see.** The exporter
only ever marked messages read; it never moved anything, so a person cleaning
the Inbox by hand each day was doing a job people assumed the script did. It
now has an opt-in `-MoveToDeleted` that marks a message read and moves it to
the Deleted Items of the mailbox it is in, on the same terms as marking read
(its report is saved, nothing on it failed). Never out of Sent Items, Drafts,
Outbox, Junk Email, Deleted Items itself or anything inside them, and never
from a search folder, which lists messages that live elsewhere. The moves
happen after each folder has been walked, because moving a message out of a
folder shifts the next one into its place and a loop that moves as it counts
skips every other message. A message that could not be marked read - a shared
mailbox the signed-in user may read but not change - was only ever mentioned
with `-Verbose`; it is now counted and named, with the reason, at the end of
every run.

Known untested, as for the rest of this script: all of it is exercised against
a fake Outlook. What the fake cannot show is how a real shared mailbox answers
`GetDefaultFolder` for Deleted Items, whether a cached-mode mailbox refuses a
move it has not finished syncing, and what the permission error says when
Outlook refuses. A first run against a real mailbox should be one folder, read
off the table's `moved` column before it is scheduled.

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

`envelope_from` is parsed, stored on every record, and read back out only by
`dmarc export`, which dumps every column. No screen and no report uses it.
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
survives `NormalizeDomain` unchanged and would render literally. Dormant while
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

## 7. Released once. Merging still produces nothing installable

**Area** `.github/workflows/release.yml`
**Severity** Low, and no longer about whether the workflow runs.

`dmarc` publishes as a genuinely single file - schema compiled in, SQLite's
native library bundled rather than sitting beside it - and the workflow proves
it on every build by copying the binary into an empty directory and making it
create a database there. That check is the point: a missing embedded schema or
an unbundled native library both look fine until somebody copies the exe
somewhere on its own, which is the first thing anybody does.

**Done.** `v1.0.0` was tagged and carries all five files - `dmarc.exe`,
`dmarc-linux-x64`, `dmarc-linux-arm64`, `dmarc-web.zip` and
`dmarc-deploy.tar.gz`. Every job is now executed rather than assembled: all
three CLI builds run their own binary (including `linux-arm64`, on an arm64
runner), and the workflow has since been dispatched manually against a branch
to prove the whole of it without publishing - its `release` job is gated on
`refs/tags/v*` and correctly skipped.

**What remains is the shape of it, and it is worth saying plainly because it
is not obvious:** the release fires on a **tag**, so *merging to `main`
produces nothing anybody can install*. `bootstrap.sh` downloads the latest
release, which means an install run straight after a merge quietly gets the
previous tag's build - the same binaries, the same version number, none of the
new work, and no error to explain it. Tag, wait for the build, then install.
`docs/AWS.md` §2.2 now says so at the point where somebody would otherwise be
caught by it.

What is also tried, on every push, is the Linux artifacts being built the same
way and installed on a fresh Ubuntu runner by `deploy/install.sh` - on x64 and
arm64 - so a tag has never been the first time the bundle was unpacked onto a
server.

The release also attaches `dmarc-deploy.tar.gz` - the scripts and systemd
units under `deploy/` - because the server has no checkout and the docs tell
somebody to run them.

The web app is not self-contained and needs the ASP.NET Core 10 runtime on the
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

**Update:** the Updates page and the boundary beneath it are now covered by
tests - what the app may write, what the agent must refuse, and that both
sides agree about the file format, which they briefly did not: the app
serialised the state as a number and the shell helper writes the name.

**Second update:** the path unit has now woken, under real systemd, in CI:
the `Install on a fresh Ubuntu` job installs the agent, writes a request the
way the app writes one (with a version that is a path-traversal attempt), and
checks that the agent consumed it and left a `Failed` status saying why.
`rollback.sh` is driven the same way, with a stamp that was never kept.

What is still untried: `update.sh` end to end, because it needs a published
release to download and there is none. No service has been stopped and
restarted by it.

**Area** `deploy/update.sh`, `deploy/rollback.sh`
**Severity** Medium.

The release channel half is tested and was driven against the real GitHub API:
the Settings page reports what it is running and correctly says nothing has
been released yet. The script that installs a release is not. It parses, its
logic is legible, and it has not stopped and restarted a real service.

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

**ARM: done, and now actually executed.** The release publishes
`linux-arm64`, and it is no longer the one build whose smoke test cannot run
it. It was cross-compiled from an x64 runner, so CI checked its ELF header
and its file size and said plainly that this was weaker than the x64 and
Windows checks, which make the binary create a database and read a report.

It stayed that way for one reason - there was no ARM runner - and that reason
stopped being true: GitHub's `ubuntu-24.04-arm` runners are free for public
repositories. `linux-arm64` is now built on an arm64 machine and started
there, and `tests.yml` runs the whole of `install.sh` on arm64 on every pull
request: the service answering, the four timers enabled, a backup taken and a
health check passed.

The architecture check stayed, and now applies to both Linux builds rather
than only the ARM one - not to Windows, where `file` is not a thing to rely
on. What it catches is narrow and worth stating accurately: that the RID
produced the ELF header it claims. It does **not** catch a runner label
changing under the matrix, because the RID rather than the runner decides the
architecture - a cross-compile produces a correct ARM header on an x64
machine, and this check passes. The thing that catches that is the "Prove the
single file actually runs on its own" step, which is now unconditional
precisely because it cannot execute a foreign-architecture binary.

This mattered more than "Low" suggested: `docs/AWS.md` recommended
`t4g.small`, so the instance the runbook told somebody to buy was the one
architecture nothing had ever run. That page now recommends `t3.small`, and
ARM is offered as what it now is - a tested alternative that is cheaper.

**Deployment: partly done.** `deploy/install.sh` now runs on every push, on
a fresh Ubuntu runner with real systemd - on x64 and on arm64 - creating the
account, unpacking the bundle, creating the database, installing the units
and starting the service. The job then checks the service is active and
sandboxed, answers on loopback, refuses a proxied request, and keeps its
cookie keys beside the database where the sandbox can reach them. That is the
Ubuntu half of `DEPLOYING.md` done for real.

And, since the scheduled jobs were added, that every one of them actually
runs: the four timers enabled and active, `dmarc-backup` writing a copy that
`sqlite3` then opens and integrity-checks, `dmarc-health` green on a fresh
install *and* failing when pointed at a directory with no backups in it -
which is what separates a check that passes from a check that is not looking
- with `dmarc-alert@` starting off the back of that failure. A templated
`dmarc-ingest@nrg` is instantiated with its own environment file and
certificate and gets as far as authentication, which is the multi-mailbox
shape this is deployed in and had never been exercised.

**One command, both operating systems.** `deploy/bootstrap.sh` and
`deploy/bootstrap.ps1` do the whole path from a fresh machine - runtime,
Caddy, the release, the service, TLS, the update agent, and as much of
sign-in and the collector as they are handed - and two more CI jobs run them
from nothing on Ubuntu and Windows runners with everything switched on:
Caddy on `localhost` with its internal CA, sign-in against Entra's `common`
tenant, and the collector with a certificate the script makes. Writing them
found that the collector unit shipped a week earlier could not run at all
(`dmarc ingest` refused to start without `--fallback` or
`--reporting-domain`, which neither the unit nor the docs passed); the
fallback now defaults to the mailbox and both come from the environment.

Still assembled rather than run: **Amazon Linux 2023**, for which there is no
hosted runner - its package names and the Caddy static-binary steps come from
the vendors' documentation and the live package repository, not from a
machine - a real Entra tenant, a real mailbox, and a hardened Windows Server
rather than the hosted runner. The doc says so in its own last section.

## 10b. A Windows install has no backup, no retention and no health check

**Area** `deploy/bootstrap.ps1`
**Severity** Medium on Windows, none on Linux.

The scheduled work is systemd units, and `bootstrap.ps1` registers only two
scheduled tasks: **DMARC ingest** and **DMARC DNS scan**. There is no Windows
equivalent of `dmarc-backup.timer`, `dmarc-prune.timer` or
`dmarc-health.timer`, so a Windows install has nothing protecting the reports,
nothing applying the retention window, and nothing that will tell you the
collector has quietly stopped - the three things the Linux path now switches
on during the install and takes the first backup for.

Nothing claims otherwise: the backup section of `RUNNING.md` says "on a Linux
install", `AWS.md` is Linux throughout, and the commands themselves are
cross-platform - `dmarc backup --to`, `dmarc prune` and `dmarc health` all run
on Windows today. What is missing is only the three `Register-ScheduledTask`
calls that would make them happen without being remembered, plus the
assertions in the `bootstrap-windows` CI job that would keep them honest.

Left undone deliberately rather than overlooked: the deployment this is
actually going into is Ubuntu on EC2, and adding Windows scheduling without a
Windows server to watch it on would be three untested tasks that *look* like
protection.

---

## 10c. Upgrading the Windows download looks like it lost your data — FIXED

**Area** `src/DmarcMonitor.Web/FirstRun.cs`, `deploy/windows-trial/README.txt`
**Severity** High for the trial, which is the copy people form an opinion from.
None on a server, where `update.sh` already runs `dmarc init-db`.

Reported by somebody upgrading their own copy: *"it didn't keep data I already
imported."* Nothing was lost - but everything about the experience says it was,
and that is the version somebody repeats to a colleague.

Two separate behaviours combine into it.

**The database lives in the folder.** `dmarc.db` and `keys\` are written beside
the executable, which is what makes the promise in the README true - delete the
folder and every trace is gone. A new download is extracted to a *new* folder,
which contains no database, so the app makes an empty one and the dashboard
opens with nothing in it. The previous folder still holds everything.

**Copying the database across is not enough, and nothing says so.** `FirstRun`
creates a database only where there is effectively none, and leaves any
existing file strictly alone - no adoption, no migration - because guessing at
somebody's file is how data really does go missing. So an old `dmarc.db`
carried into a new folder is opened at whatever schema it had. Against v1.1.1
that is a database with no `mta_sts_mode` and no `raw_hash`, and the pages that
touch them report a database they cannot read. `dmarc init-db` is the upgrade
path and applies the migrations correctly; it is simply not mentioned anywhere
a person upgrading would look.

The whole procedure today, none of which is written down:

1. close the app,
2. copy `dmarc.db` (and `keys\`, to stay signed in) into the new folder,
3. run `dmarc.exe init-db` there once,
4. start it.

**Fixed.** The application now recognises a database that is ours but behind
the schema this build expects. In local trial mode it applies the migrations
itself and logs each one; anywhere else it does not, and says which command
will, because migrating a production database because a service restarted is a
decision an operator makes and `update.sh` already makes it explicitly. A
database from a NEWER build is named rather than touched, and one whose schema
cannot be read is left alone. Proved against the NRG database at schema `0008`,
nine migrations behind, carried to `0017` with its 1,652 reports intact. The
trial README carries the three steps for bringing a database to a new version.

## 11. The apply path has never written to a real zone

**Area** `src/DmarcMonitor.Core/Remediation/`, `dmarc fix`, the Fix page
**Severity** Medium. This is the feature the product exists for, and its
last step is untried.

Everything up to the provider is exercised against real data: `dmarc fix
--all` on the 1,687-report database plans the two `sp=none` removals
(client-a.example, client-b.example), plans acme.example's move to quarantine, and
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

## 12. Nothing tells anybody what it found

**Area** the whole product
**Severity** High for a managed service, and the largest single gap in it.

Every finding on every page is computed when somebody opens the page. There is
no findings table, so nothing has an owner, a status, a due date or a history,
and nothing can be acknowledged, assigned, suppressed or closed. A sender
awaiting the customer's confirmation, a DNS drift event, a remediation item and
an alert are the same row with different types, and that row does not exist.

The consequences, in the order they will be felt:

- **Alerting is one path, for one kind of finding.** DNS drift is detected
  on every scan, written to `dns_drift_events`, acknowledged on the domain's
  page, and sent to a signed webhook ([`WEBHOOKS.md`](WEBHOOKS.md)). Nothing
  else is sent anywhere: no email, no Slack without a relay in front of it,
  and no sender, reachability or collection finding goes out at all. Those
  are still learned about by opening the app, or by `dmarc health`'s
  `OnFailure=` for collection that has stopped.
- **The webhook has no Windows schedule.** `dmarc notify send` runs by hand
  there; nothing runs it after the scan.
- **Sender classification is not remembered.** It is good, and it is computed
  per report: nothing can be confirmed as approved, given a business owner, or
  marked as an exception with a review date.

See `docs/MSP-PLATFORM.md` for how this sits against what an MSP platform is
expected to be. It is one table and the workflow on top of it, and four of the
brief's ten Phase 1 items collapse into it.

## 12a. Anomaly detection, as part of the alerting that 12 is missing

**Area** a new nightly job over each client's file, writing findings (12b)
into the organization's file. `alerts` in `db/client-schema.sql` was the
planned target and is retired by 12b before anything writes to it.
**Severity** Medium on its own. High as the first thing to put through the
alert path, because the alert path is what an MSP is paying for.

An autoencoder was proposed for this. Not first, and this is why: an
organization's month is a few thousand aggregate rows, which is enough to
train a small network and not enough to know what it learned; and an alert
that cannot say *why* it fired is one an on-call tech mutes within a week. The
practice that holds up in MSP operations is the other way round - a statistic
a human can check, wired into the on-call path, with the model earning its
place by beating that statistic on the same data.

**Phase 1 - baselines, per client, from that client's own file.** Nightly,
after the collector, writing findings (12b) with a `dedup_key` per
(type, domain, service or network) - never per day and never per address,
so a re-run updates `last_seen_at` rather than firing twice:

- *New failing source*: an address first seen for this client today, failing
  DMARC, above a floor of messages. This is the impersonation case, and the
  threat indicators already know whether the same address hit other clients -
  that count goes in `payload_json` and raises severity.
- *Volume anomaly*: today's count from a known source against that source's
  own history for this client - median and MAD, not mean and standard
  deviation, because one spike must not inflate its own baseline. Needs a
  minimum of history (seven days) before it may fire at all.
- *Pass-rate drop*: a domain whose authenticated share falls a set number of
  points below its 30-day rate, which is a broken DKIM key or an SPF edit
  before the customer notices bounces.

Every alert names the client, the domain, the address, the number, the
baseline it was compared with and the receiver that reported it. A tech can
verify each of those in the source page in under a minute; that is the
standard, not the model's confidence.

**Phase 2 - the MSP operations side, which is most of the value.**

- *Delivery* - **built in 12b**: open findings are read by `dmarc health`
  (a check naming them) and by `dmarc findings list`, which prints open ones
  and exits 1 when a critical is open - the shape every RMM and PSA already
  knows how to poll. And they go out the same way DNS drift does: the signed
  webhook ([`WEBHOOKS.md`](WEBHOOKS.md)) sends `dmarc-monitor.finding.v1`
  for every finding type alike, and the PSA is the second destination kind
  on that channel - see the ConnectWise section below. Into the PSA rather
  than into somebody's inbox. An anomaly type lands as rows in the same
  table, with nothing new to deliver.
- *Workflow*: acknowledge, suppress with a reason and a review date, resolve.
  This is the findings table issue 12 asks for and 12b designs; anomaly
  findings are among its first rows, not a separate system.
- *Per-client tuning*: a client whose newsletter tool sends 5,000 on the
  first of the month is not an anomaly; an exception (12b) with a reason and
  a review date is how that is remembered, carried by client id so an erasure
  or a move takes it along.
- *Reporting*: the month's alerts and how they were closed become a section
  of the client report - "3 new senders reviewed, 1 blocked" - which is the
  evidence of monitoring the customer is billed for.
- *Cross-client*: the organization-wide view (one address, several clients)
  already exists in threat intelligence; alerts feed it rather than repeat it.

**The PSA is ConnectWise PSA (Manage).** Decided 28 Sep; **built the same
day for DNS drift** (migration 0021, `docs/CONNECTWISE.md`), so the
integration is proved against events that exist today and phase 1's alerts
flow through it when they arrive. It cannot receive the signed generic POST -
there is no inbound webhook-to-ticket in it - so it is reached through its
REST API, as a second *kind* of destination on the channel `dmarc notify`
already runs, not as a parallel system. What that reuses without change: the
pending-events query (oldest first, stop at the first failure so a receiver
never sees things out of order), the `webhook_deliveries` ledger, the secret
store for the credential, the `dmarc-notify.service` schedule after each
scan, and the `dmarc health` "stopped delivering" check. Still to do once it
has run against the real instance: confirm the 100-character summary cap and
the note fields against the instance's API version, and decide whether ticket
state should be read back to resolve alerts (one way for now).

- *Authentication*, as ConnectWise documents it: HTTP Basic with
  `companyId+publicKey:privateKey`, plus a `clientId` header registered at
  developer.connectwise.com; a request without the header is a 401. All four
  go in the secret store under one credential ref, as the webhook's address
  and key do. The API member they belong to gets the least the integration
  needs - add and edit on the alert board's tickets, inquire on companies -
  and nothing else, and the product's docs say so.
- *Configuration*, per organization: `dmarc notify set --kind connectwise
  --site <api host> --board <name> ...`, with the board's own default status,
  and a severity-to-priority map (critical and warning; info is never a
  ticket). `webhooks.tenant_id` is UNIQUE today - one destination per
  organization - and becomes UNIQUE per (organization, kind), so a Teams
  relay and the PSA can both be fed. That is a migration (0021), with a
  `kind` column defaulting to `webhook`.
- *Client to company*: an explicit mapping, `connectwise.company_id` in the
  existing `client_settings`, set with `dmarc client set --client <slug>
  --connectwise-company <id>` after a `dmarc notify companies --search
  "Acme"` lookup. Never matched by name: a slug that happens to resemble a
  company identifier would file one customer's alert on another customer's
  account, and that is the cross-tenant bug in a new coat. An unmapped client's
  alerts stay in the dashboard and are named by `dmarc alerts` as unfiled.
- *One ticket per finding, not per event*: an alert's `dedup_key` maps to one
  open ticket. A repeat while it is open adds a note (`POST
  /service/tickets/{id}/notes`) rather than a second ticket; once a tech has
  closed it, the next occurrence opens a new one that names the old. The
  ticket id is kept beside the delivery record (`webhook_deliveries` gains a
  `remote_id`), and a short marker of the event id goes in the summary so a
  create whose answer was lost can be found again rather than repeated.
- *The ticket itself*: `summary` (short - ConnectWise caps it; treat 100
  characters as the limit until the build confirms it) reads `DMARC:
  <client> - <one line>`; `initialDescription` carries the evidence the
  alert already has - client, domain, address and its confirmed name, count,
  baseline, reporter - and the dashboard link when `--link-base` is set.
  Required by the API are summary, board and company; status and priority
  fall back to the board's defaults when not mapped.
- *Direction*: one way. The PSA is the system of record for the work, so the
  product never closes a ticket; resolving an alert in the dashboard adds a
  note. Reading ticket state back to resolve alerts is a later, separate
  decision.
- *Volume and limits*: a nightly run is a few dozen calls at most, well under
  any published throttle (the Power Platform connector, for comparison, allows
  100 calls a minute per connection). The channel's stop-at-first-failure
  already handles a 429 the same as an outage: the rest wait for the next run.
- *What leaves the box*: client name, domain, source address and its name,
  counts and the baseline. Never a report, never a header. `DATA-HANDLING.md`'s
  outbound list gains the ConnectWise API host; the destination is the MSP's
  own PSA, which already holds the client's records.
- *Proving it*: unit tests against a fake ConnectWise (the notifier already
  takes an `HttpMessageHandler` for this), asserting the auth header, the
  marker, the note-not-ticket path and the unmapped-client refusal; then
  `dmarc notify test --kind connectwise` creates one ticket on a board the
  operator names, on the real instance, and prints its number. There is no
  public ConnectWise sandbox to run CI against, so that manual step is the
  acceptance test and is written down as such.

**Phase 3 - the autoencoder, if it earns it.** Train per organization, not
per client (the data is too thin per client), on per-source-per-day feature
vectors; score reconstruction error; compare against Phase 1 on the same
month using the alerts techs actually acted on as labels. Ship it only where
it finds something Phase 1 missed and a tech agreed was real. If that never
happens, the answer was the baseline, and that is a fine answer.

**Not to do**: alert on every DMARC failure (that is what the client report
is for), send anything by email from the box (issue 12's reasoning), or train
on all organizations together (one MSP's customers are not another's
baseline, and the client files exist to keep them apart).


## 12b. The findings lifecycle: one table under 12 and 12a, kept to email authentication and DNS

**Area** migration 0022 in `db/schema.sql` - findings, their timeline,
exceptions and sources, in the organization's file; `alerts` in
`db/client-schema.sql` dropped by client migration 0002 before anything wrote
to it; the acknowledgement columns on `dns_drift_events` read for history
only; the Operations page; `dmarc findings`; the notify channel reading
findings.
**Severity** High. This is issue 12, designed and built. Everything in 12a
lands in it.

**Decided 29 September, built the same week (#62).** This product stays the
operational control plane for domain and email authentication. The lifecycle
is generic enough that a second product could write to it, and no
first-class feature is built for one: every finding type is DMARC-native,
identity, endpoint, vulnerability and baseline-drift findings stay in the
assessment and MSP-Ops tools, and nothing here ingests them. The two share
a finding contract, not a database model. The reason is the one that has
held all month: one thing done to the standard of `dmarc simulate` beats ten
things done to the standard of a viewer.

[`FINDINGS.md`](FINDINGS.md) is the reference for what was built. What
follows is the design as reconciled against the code, the corrections made
on the way, and what remains.

### Where findings live

Every client's data has its own SQLite file since #55. A finding is about one
client, so the client file looks like the place, and it is the wrong place for
a queue:

| findings in | the queue read | a decision, an exception | isolation |
|---|---|---|---|
| client files | a TEMP-table union of every file on every page load | one write per client file | strong by construction |
| the organization file | one table, one index | one row | carried by `client_id`; `dmarc client erase` already checks every such table |

They are in the organization's file. They are operational state *about* a
client - like the audit log, and like `webhook_deliveries` already - not the
client's data. The discipline that buys is that a finding never carries the
evidence itself: a DNS record's text and a report are client data and stay in
the client file, and the finding points at them (`evidence_ref`) and hashes
what a resolving read must serve (`expected_ref`). Both consequences are
built and tested: erasure covers findings, exceptions and events; a domain
reassigned carries them.

### Two states, not one status

The design as first written had one `status` column running from `open`
through `fixed_awaiting_dns` to `resolved`, with `sla_due` and `assigned_to`
beside it. Reconciling it against the specification for the shared contract
changed that in three ways, each of which the tests now pin:

- **`source_state` and `analyst_state` are separate columns.** What the
  source last saw (`active`, `resolved`, `unknown`) and what a person decided
  (`unreviewed`, `investigating`, `action_required`, `benign`,
  `accepted_risk`, `closed`) never move each other. Closing a finding whose
  record is still wrong leaves the record wrong; the next observation says so.
- **Failed collection is `unknown`, never resolution.** A failed DNS read, a
  collector whose last run failed, an organization with nothing stored in 36
  hours: every finding the source has open there becomes unknown and none is
  cleared. Silence is evidence only when somebody was listening.
- **No SLA and no assignee.** This is a detection and verification console;
  the ticket is in the PSA, and that is where work is owned and timed.
  Putting a second work queue here was the giant-merged-codebase mistake in
  miniature.

### The tables, as built

`findings`: identity (`tenant_id`, `source_id`, `client_id`, `dedup_key`,
unique), `domain_id`, `type` and `rule`, `severity`, `title`, the two states,
`remediation_stage`, `first_observed_at`, `last_observed_at`,
`observation_count`, `absent_count`, `reopened_count`, `evidence_ref`,
`expected_ref`, `related_finding_id`, `payload_json`. `finding_events`:
append-only, kind, actor (a source's id or a person), from, to, note.
`finding_exceptions`: reason, approver, compensating control, approved date,
review date (required), optional expiry, one open per finding.
`finding_sources`: one row per engine per client or organization, last
attempt, last success, last failure, last error; health computed when read.

The PSA side needed one change: `remote_key` is now the finding's id rather
than domain plus record type, so a ticket follows the finding whatever its
type, and the ticket's number is written back as a `TicketCreated` event.

### Identity

A finding is (`source`, `client`, `dedup_key`). The engine that raises it
re-observes it on every run: seen again moves `last_observed_at` and
`observation_count` and inserts nothing; not seen on N successful
observations (one for DNS, three for reports; the type says) resolves it by
the source; seen again after that reopens the same row with a `Reopened`
event and asks to be reviewed again. The key is the thing, not the
observation: DNS keys on domain plus record type, so a record that goes from
weakened to removed is one finding whose type and severity moved, and one
ticket. The volume-anomaly dry run in 12a remains the counter-example.

### The finding types

Built: `DNS_DRIFT`, `DMARC_POLICY_WEAKENED`, `DMARC_POLICY_CHANGED`,
`SPF_INVALID` and `SPF_CHANGED` from the rules already in `DnsDrift.cs` - the
specification names them as types, so they are types, each still one finding
per record; `REPORTING_STOPPED` from the quiet-domain judgement `HealthFacts`
had, per domain, only for a domain that reported in four of the five weeks
before its last report, and only while the collector was listening;
`REMEDIATION_PENDING_VERIFICATION` for every change applied from the Fix
page.

Deferred, each with its reason: `dkim_selector_missing` (selectors are not
diffed nightly yet), `mta_sts_failure` (needs the nightly policy fetch),
`tls_failure` (a small detector over `tls_failure_details`), `new_sender`,
`alignment_degradation` and `volume_anomaly` (12a phase 1), and
`unknown_sender`, which cannot exist until a sender can be approved. Each
lands as a source writing rows to the same table; none needs a new lifecycle,
a new delivery path or a new page.

### The Operations page

Six questions, in order, each a filtered view of `findings`: what broke, what
changed, what needs review, awaiting verification, excepted (with the review
date), and the engines. A finding opens to its history and to what a person
may decide: Tech marks as seen and records a decision with a note; Engineer
records an exception (reason, approver, compensating control, review date,
optional expiry) or ends one. Every action writes `finding_events` and the
audit log. This is not the dashboard: the triage table answers "how healthy
is the estate"; this page answers "what did the engines find, and did the
fix take".

Not built, on purpose: assignment, SLAs, and reading the ticket's state back
from the PSA onto the finding (the number is there; the state is a later
read).

### Verification, which is where DNS is different

Built as designed, with one simplification: the stages are `dns_pending`,
`dns_verified` and `effectiveness_pending`, and DNS verification is one read
serving the applied value (the verify poll after applying, or the nightly
read) rather than two consecutive nights, because the poll uses its own
uncached resolver and the nightly read is hours later. The reporting evidence
is the `policy_*` columns each receiver reports, matched on `p`, `sp`, `pct`,
`adkim` and `aspf` for a period after the change; fourteen days after DNS
verification without one resolves as *verified by DNS only* and says so; a
rollback withdraws the finding as not verified and restores the drift
finding's expectation.

**Still open:** whether the verify poll and the nightly read ask the domain's
authoritative servers or only a resolver with no cache of its own. Until that
is confirmed, DNS verification is a read past the caches this product
controls, not past every cache.

### The anomaly model, corrected for DMARC data

The feature list proposed (messages per source, new-source count, SPF, DKIM,
alignment and DMARC failure ratios, receiver count, report volume,
disposition ratio, unknown-sender ratio) is right. What it is computed *over*
is where this goes wrong, and each of these is a rule for phase 1 as much as
for phase 3:

- **Time base is the report period, not arrival.** A receiver's report covers
  `date_begin` to `date_end` and arrives a day or three later; bucketing by
  arrival makes every late report a drop followed by a spike. Bucket a day by
  the period's midpoint, and score a day only once its lag window has closed
  (two days).
- **Features are deviations from the domain's own baseline**, not raw counts:
  each feature as a z-score against that domain's trailing 28-day median and
  MAD. A per-organization model fed raw counts learns big domains versus
  small ones and nothing else.
- **Ratios on small volume are noise.** Smooth them, (fail + 1) / (n + 2),
  keep the log of the count beside each, and never score a domain-day under a
  floor of messages.
- **Distribution shift is one number.** "Pass rate is fine but the sources
  changed" is the Jensen-Shannon divergence between today's source-share
  vector and the trailing 28-day share, plus the entropy of the share. One
  scalar each, rather than a variable-length vector the model cannot take.
- **Receiver count is the reporting-gap signal.** Google stopping is a count
  going from three to two before it is a volume drop.
- **Explainability is a requirement.** The finding's title names the three
  features with the largest reconstruction error, in the domain's own
  numbers: "volume 90% under the 28-day median; receivers 3 → 1". A score
  alone is a finding a tech mutes.
- `unknown_sender_ratio` waits for sender approval, as above; until then the
  feature is the share from sources first seen inside 30 days.

### What remains

1. `dkim_selector_missing`, `mta_sts_failure` and `tls_failure`, each a small
   detector on data the product already stores, writing to the same table.
2. Phase 1 of 12a (`new_sender`, `alignment_degradation`, `volume_anomaly`)
   on the features above, as sources.
3. The ticket's state read back from the PSA onto the finding.
4. Phase 3 of 12a, gated as 12a says.
5. Sender approval, and with it `unknown_sender`.
6. The authoritative-server question above.

**Not to do**: ingest another product's findings (the schema allows it; the
product does not, until a second product exists); put findings in client
files for the sake of symmetry; close a ticket from this side; send anything
by email from the box (issue 12); add assignment or SLAs here; or let the
anomaly types into the queue before they can name their own evidence.

## 13. The client report is one document, and nothing sends it

**Area** `src/DmarcMonitor.Core/Reporting/ClientReportRenderer.cs`,
`ClientReportPdf.cs`
**Severity** Medium. It is the monthly deliverable.

The report now carries a posture summary, a classified sender inventory, the
failure causes, per-domain enforcement readiness and a remediation register
with an owner and a definition of done for each item, and `dmarc report`
renders it server-side as a PDF with the product's own header, footer and page
numbers, the day-by-day chart, and the impersonating sources grouped by
operator. What it does not have:

- **From an outside review of the one client's report (24 Sep)**, worth
  adding and not yet done: an enforcement-readiness panel under the verdict
  (policy / senders identified / unknowns / coverage / ready for reject, each
  pass-partial-no with its evidence); a "decision needed" line naming what the
  client must confirm; the full sender inventory as a CSV appendix rather than
  on the PDF; and a one-line DNS posture strip (DMARC, SPF, DKIM, MTA-STS,
  TLS-RPT, last change). The four related figures are now reconciled: the
  verdict, the Critical and High findings all quote what the named services
  failed (224 on one client), the sender row shows "229 (224 failed)",
  and what receivers did (234) is its own labelled sentence.
- **One report, not three.** The brief asks for an executive report, a
  technical report and a QBR; this is one document that sits between the first
  two.
- **No CSV appendix.** `dmarc export` writes the raw data, which is not the
  same as a workbook of the report's own tables.
- **Nothing schedules or keeps it.** Generated on demand, never stored, so
  there is no history of what was sent to whom.

## 14. v1.1.2 carries a stray screenshot

**Area** the repository, and the `v1.1.2` tag
**Severity** None to anyone using it. Recorded because a release should not
contain files nobody meant to ship.

`undefined/fix-nrg.png`, 238 KB, was committed by accident: a Playwright script
ran with an unset environment variable, wrote its screenshot to a directory
literally named `undefined`, and a later `git add -A` swept it in. It is in the
merge that became `v1.1.2`.

It reaches nothing that is published. The release builds binaries from source
and attaches those; no shipped artifact contains it, and the source zip GitHub
generates is not something the install path uses.

Removed from `main`. The tag keeps it, because a published tag is not worth
moving for a file nobody will see — the next release will not have it.

**The lesson worth keeping:** `git add -A` from the repository root adds
whatever a tool happened to leave there. Scratch output belongs in the
scratchpad directory, not beside the checkout.

## 15. Open from the Critical/High audit of 23 September

**Area** several, named below
**Severity** High unless marked. Every item here survived three independent
attempts to refute it, or was found by one finder and not yet verified
(marked *unverified*). The Criticals from the same audit are fixed (#46), as
are the role gates on Updates and the brand name, the Settings page listing
every organization, provider configs resolving a slug across organizations,
SERVFAIL read as a dead SPF include, ingest never reading rule-sorted child
folders, the interpolated tenant id, a cross-site switch of organization,
and update.sh not checking SHA256SUMS.txt. Since then: the DNS apply path
that resolved a domain by name alone, and the local trial answering to any
Host name (both below, under Fixed).

**Multi-organization installs only.** One organization, which is every install
today, is not exposed by any of these.

- **`dmarc client set-group` ignores `--org`** and sets the customer group on
  every client with that slug in every organization. *unverified*

**Everywhere.**

- **Windows install ACLs.** `bootstrap.ps1` creates `C:\dmarc\data`, `app`,
  `bin` and `dotnet` with the ACL inherited from `C:\` (Users read,
  Authenticated Users modify). Any local account can read the database and the
  cookie key ring, and replace binaries that run as LocalService. Fix: break
  inheritance on `C:\dmarc` and grant only SYSTEM, Administrators and
  LocalService.
- **`bootstrap.ps1 -Release <tag>` is a no-op on an installed machine.** It
  skips the download whenever `DmarcMonitor.Web.dll` exists, restarts the old
  build and prints Done. This is the documented Windows update path.
- **The Linux secret key sits beside the ciphertext**, and DEPLOYING.md §8
  says to copy that directory offsite and that a stolen backup cannot yield
  the Cloudflare token. It can. Either move the key out of `secrets/` or
  correct the document.
- **`GITHUB_TOKEN` is passed to curl as an argument** in `update.sh` and
  `update-agent.sh`, readable by any local account in `/proc/<pid>/cmdline`.
  Use `curl -H @file` or a netrc. Related: `Updates:Token` lives in plain
  appsettings rather than the secret store.
- **`AllowedHosts` is `*` on a deployed instance.** Caddy in front forwards
  only the names it has a site for, and the service binds 127.0.0.1, so
  nothing reaches the app under a name it was not given; the app itself
  accepts any. It cannot simply be narrowed, because the same app answers
  `mta-sts.<client domain>` for every client from the Host header, so the
  restriction has to leave that one path out. Defence in depth, not an open
  door.
- **A person in more than about five Entra groups reaches the app with none**
  (found while turning on sign-in in the Windows trial, not by the audit).
  Sign-in uses the ID-token flow, for which Entra sends no groups claim above
  a handful - its documentation says five in one place and six in another -
  and a `hasgroups` marker instead. The "No organization" page now says when
  this is the reason, and DEPLOYING.md §5 and RUNNING.md recommend "Groups
  assigned to the application", which counts only a person's direct memberships
  of groups assigned to the app. That keeps the count down but does not remove
  the limit (somebody in more than about five assigned groups still gets the
  marker), needs every group the app uses to be assigned (one left out is
  silently absent, and the app cannot tell that from being in no group), and
  needs Entra ID P1. Not resolved: the app does not ask Microsoft Graph for the full list,
  because the ID-token flow gives it no access token to ask with, and that
  option is unavailable on Entra ID Free. Doing it properly means the
  authorization-code flow with a certificate (limit 200, and `_claim_names`
  says where to look) or app roles in place of groups. Either changes the
  sign-in registration every install already has, so it is a decision rather
  than a patch.
- **`AssignDomainAsync` with no tenant** - the master account's path - takes
  the first client with that slug when two organizations hold one. Every
  command and page passes a tenant, so nothing reaches it today.
- **`sp=` removal is planned as a safe fix** on every domain without checking
  the reports for failing subdomain mail, and is applied under the Tech role.
- **The "policy served elsewhere" MTA-STS guard is Fix-page only.**
  `dmarc fix` still tells the operator to run `dmarc mta-sts set` for a domain
  that serves its own policy, and `mta-sts set` does not check.
- **A crafted zip aborts the whole import run** instead of skipping one file:
  `ZipArchive.Entries` throws lazily outside the try in
  `ReportAttachment.FromZip`.
- **`ClassOf` passes an IP to a catalog keyed on host names**, so the "known
  provider" classification never fires and a gateway reads as "unrecognised
  entirely".

**Threat intelligence and naming.** *unverified*

- `dmarc intel --export` writes the raw `source_ip` from an unauthenticated
  report as a blocklist line, so a forged report can put `0.0.0.0/0` into a
  firewall file; a DKIM selector containing a newline adds a line of its own.
- Indicators are never aged out once rated High.
- A sender-chosen PTR becomes a vendor label ("Microsoft 365") and the source's
  name on the client report, with no forward-confirmed check.
- Forged mail whose envelope sits under a catalogued gateway suffix is
  classified as forwarded.

**Other.** *unverified*

- `dmarc prune --aggregate-days 1O95` silently becomes 400 and deletes:
  `Args.Int` substitutes the default for anything that does not parse.
- The zone audit flags the RFC 7489 `*._report._dmarc` wildcard as Breaking,
  and a Cloudflare flattened apex CNAME likewise.

## 8. Smaller things

| area | what | how |
|---|---|---|
| `ClientReportRenderer` | The `(s)` plural convention is everywhere — "1 service(s) you use is" — which is honest but reads as unfinished in a client-facing document | Pluralise properly for the common nouns; the `Was`/`Is` helpers in `ReportNarrative` already show the pattern |
| `ReportCommand` | `--provider` defaults to the literal string "your IT provider" | Either make it required, or read it from configuration so it is set once |
| `ClientReportRenderer` | The report's domain table does not mention `pct`, though the domain page does | Carry `Pct` through and say "on N% of mail", same wording as `DomainView` |
| `ClientCommand` | Prints "Added X as 'slug'" while the Clients page says "filed as" | Pick one phrasing |
| `ReportPeriod` | An explicit `--month` can select the current, incomplete month and the report does not say so | Say "covers 1–17 Sep, in progress" when the period has not ended |
| `ReportStore` | Records stored before the store chose between several passing signatures by alignment (see "Fixed today", 8) keep the first passing one, which for a Google Workspace domain is `google.com`'s own. The raw reports are not kept, only a hash, and a report already stored is skipped when read again, so nothing can re-derive them in place | Read the original report files into a new database. An in-place repair would need the raw reports kept |

---

## Fixed today, for reference

These were all live in front of a client and are all now covered by tests that
fail without the fix.

1. **A customer's own mail relay called a forger.** `35.174.145.124` rated High
   against seven of ten clients. It is a gateway carrying their outbound that
   breaks a share of its own signatures in transit. Fixed in three places; the
   rule is that passing even once *for that domain* is what a forger cannot do.
2. **The client report accusing the same relay.** One client's August report said
   177 messages were "sent by someone who is not you". It was their own mail.
3. **"210 of those 137."** The impersonation sentence reused a figure counting
   every failing message on every enforcing domain.
4. **Indicator counts disagreeing with their own lists.** "7 domain(s)" above a
   list of nine: the count was windowed, the names were not.
5. **"0 silent" while five domains had gone dark** for between 14 and 128 days.
   Silent counted only domains that had never reported, not ones that stopped.
6. **The DNS apply path took the first domain with that name.** On an install
   holding the same domain in two organizations, an Apply could file its audit
   row under one organization's client and write with the other's provider
   token; a rollback, an MTA-STS write and the public policy endpoint had the
   same shape. A domain is now looked up inside the caller's organization, and
   a name that two organizations hold is refused when none is named:
   `dmarc fix`, `dmarc dns` and `dmarc mta-sts` take `--org`, the Fix page
   passes the signed-in person's organization, a change carries the
   organization it was made in, and the public endpoint serves nothing for a
   name two organizations have policies for. Covered by
   `CrossOrganizationDnsTests`, which fail without the fix.
7. **The local trial answered to any name.** With no sign-in, the only guard was
   that the connection came from loopback, so a web page could rebind its own
   name to 127.0.0.1 and read the app from the trial user's browser. It now
   answers only to `localhost`, `127.0.0.1` and `[::1]`. Covered by
   `ProxyTests`.
8. **A record signed twice was filed under the wrong signature.** A Google
   Workspace message carries two DKIM results, `google.com`'s own and the
   domain's key, and both verify. The store kept the first passing one, which
   is Google's and does not align with the From domain, so a row said its pass
   rested on a signer that is not the domain's. `dmarc simulate` read DKIM-only
   mail signed that way as unexplained and left it out, and read mail passing
   both ways as resting on SPF alone: on a real Google Workspace domain it
   reported mail as SPF-alone that the receivers had passed on DKIM as well.
   The store now keeps a passing result that aligns with the From domain if
   there is one, then any passing one, then the first, for DKIM and SPF alike.
   Covered by `ReportStoreTests`, which fail without the fix; records already
   stored keep the earlier choice (see "Smaller things").
9. **A reason of "other" was read as a forwarder, and a carve-out for
   `sampled_out` matched nothing.** Any reason a receiver wrote beside a record
   made the tool treat the failure as expected, and `dmarc explain` said so:
   "the receiver recognized a forwarder or mailing list. Not an attack and not
   a misconfiguration. Nothing to do." One receiver writes `other` beside mail
   it quarantined exactly as the policy asked. The message that showed it was
   signed on the protected domain with a selector nobody had published, from a
   home broadband address in another country, and the tool told the operator
   to ignore it. Every table that leaves forwarded failures out left it out
   too: the sending sources, the threat indicators, the domain page, the
   authenticated / overridden / unauthenticated split and the client report.
   One of those queries did try to keep `sampled_out` in, which is how a
   receiver marks what `pct` let through and so what somebody ramping the
   policy most needs to see, but it spelled the reason with an underscore and
   the store writes `sampledout`, so the exception never applied. One rule,
   `PolicyOverrides`, now says which reasons excuse a failure (forwarded,
   trusted forwarder, mailing list, local policy) and builds the condition
   every query uses from the spelling the store writes.
   The same report put its results in capitals ("Fail"), and every query asks
   for `'pass'` exactly, so a receiver that wrote "Pass" would have had its
   passing mail counted as failing; results are lower-cased on the way in. Its
   signature on the domain was reported as `permerror` because no key existed
   for the selector, which is a forged signature however a receiver words it,
   and now counts as one beside `fail`. Covered in every reader by tests that
   fail without the change. The reason is read when a query runs, so what is
   already stored is corrected too; only the `fail_reason` label in an
   export of a record stored earlier still says `override`. Not changed:
   `local_policy` still excuses, though it says only that the receiver chose to
   deliver the message, which is not quite the same as the failure being
   expected.
