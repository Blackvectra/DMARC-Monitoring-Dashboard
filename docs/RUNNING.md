# Running it

Two pieces. They share a SQLite file and nothing else.

- **`dmarc`** — collects reports and writes client reports. One binary, no
  .NET install, no checkout. Runs on a schedule.
- **The web app** — the screens. Reads the database the CLI writes, and
  writes only when onboarding a domain or importing a folder.

Neither needs the other running. The CLI works with no web app; the web app
shows an empty state until something has been collected.

---

## Quickest possible start: the Windows trial download

Nothing installed at all. `DMARC-Monitor-Windows.zip` from the latest release,
unzipped, and `Start DMARC Monitor.cmd` double-clicked. A browser opens on the
dashboard.

Unblock the .zip before extracting it (right-click → Properties → Unblock),
and expect SmartScreen to object the first time: these binaries are not
signed, and [docs/SIGNING.md](SIGNING.md) covers what that would take. The
`dmarc.exe` in the same folder is the command-line tool — it sorts directly
above the application in Explorer and is not it.

There is no .NET runtime to install, no administrator prompt, no service and
no server. The application creates its own database in the folder it was run
from — that is the only state it has, along with the `keys\` directory beside
it that signs your session cookie — so deleting the folder removes every
trace. Put data in by dropping report files onto the Import page, or with the
`dmarc.exe` in the same folder:

```
dmarc.exe import --from "C:\some-folder-of-reports"
```

It is the same build a server runs, in **local trial mode**: it serves
requests from that machine and refuses anything that arrived through a proxy,
and says so in a banner on every page. That makes it safe on a laptop and
wrong on a server — for a server, see [`DEPLOYING.md`](DEPLOYING.md), which
starts from the same application with sign-in configured.

## Quickest possible start from the command line

No mailbox, no app registration, no configuration. Enough to see whether the
product is worth the rest of the setup.

```
dmarc init-db
dmarc import --from C:\some-folder-of-reports      # or the export zip itself
dmarc client add    --name "Acme Corp"
dmarc client assign --domain acme.com --client acme-corp
dmarc report --client acme-corp --provider "Your Company"
```

`dmarc explain <file>` reads a single report and says what it means in plain
English, with no database at all. It is the fastest way to check a report
somebody has just forwarded you.

### Organizations

Clients belong to an organization, and an organization's people see its
clients and domains and nothing else. One install starts with one
organization, filed as `local`; a second company on the same install is a
second organization:

```
dmarc org rename --org local --name "NRG Tech Services"
dmarc org add    --name "NextLayerSec" --group <entra security group object id>
dmarc client add --name "Corner Post" --org nextlayersec
dmarc client assign --domain cornerpost.example --client corner-post
dmarc import --from C:\nextlayersec-export --org nextlayersec
```

Who belongs to which organization is an Entra security group; the master
group, named in `Auth:MasterGroupId`, sees them all with a switcher in the
sidebar. Without sign-in configured, whoever is at the machine is the
master. docs/DEPLOYING.md step 5 has the Entra side. Every page - Triage,
Domains, Fix, Sources, Reports, Clients - is scoped to the organization being
looked at, and within it can be narrowed to one client. Assigning a domain to a
client in another organization moves it there, history and all.

### Roles, customer logins and branding

Within an organization a group per role says what its members may do: a
**viewer** reads, an **operator** also assigns domains, imports and applies
fixes, an **admin** also runs the organization's settings. A client can have a
group of its own, whose members see that one client read only — the customer's
own login. Each organization can dress the app in its own color, logo, name
and contact details.

```
dmarc org set-group --org nextlayersec --role admin  --group <id>
dmarc org set-group --org nextlayersec --role viewer --group <id>
dmarc client set-group --client corner-post --group <id>
dmarc org brand --org nextlayersec --color '#0f766e' --provider-name "NextLayerSec" \
    --contact 'dmarc@nextlayersec.io' --logo ./logo.png
```

All of it is on the Settings and Clients pages too, for an admin.
docs/DEPLOYING.md step 5 has the table and the Entra side.

---

## The web app

### Locally

```
cd src/DmarcMonitor.Web
dotnet run
```

Then <http://localhost:5212>.

With no `AzureAd` configured it runs in **local trial mode**: no sign-in, and
it refuses connections from anything but this machine. Every page says so in a
banner, and Settings says it again with the detail.

### On a server

The published bundle needs the **ASP.NET Core 8 runtime** on the host — unlike
`dmarc`, it is not self-contained.

```
dotnet DmarcMonitor.Web.dll
```

Configure it with `appsettings.json` beside the DLL, or environment variables.
Environment variables win, and double underscore is the separator:

| setting | environment variable | what it is |
|---|---|---|
| `Database:Path` | `Database__Path` | the SQLite file. **Use an absolute path.** |
| `Reporting:ProviderName` | `Reporting__ProviderName` | how you are named in client reports |
| `AzureAd:TenantId` | `AzureAd__TenantId` | turns on Microsoft sign-in |
| `AzureAd:ClientId` | `AzureAd__ClientId` | the app registration for sign-in |
| `Auth:AllowLocalModeRemotely` | `Auth__AllowLocalModeRemotely` | see the warning below |

`Database:Path` is resolved to an absolute path at startup and printed in the
log, because a relative path resolves against whatever directory the service
was started in — which is rarely the one you expect, and produces an empty
dashboard rather than an error.

### Before it is reachable by anyone else

**Configure `AzureAd`, or leave local mode alone.** With no sign-in
configured the app binds to loopback and refuses everything else. Setting
`Auth:AllowLocalModeRemotely` removes that guard **without adding
authentication**: anyone who can reach the port can read every customer's mail
data. It exists for a container where loopback means something different, and
it is the wrong answer to "I cannot reach it from my laptop".

The sign-in app registration is separate from the ingest one and needs far
less: a web platform with redirect URI `https://<host>/signin-oidc`, and no
API permissions beyond the default sign-in scopes. It authenticates your
staff; it never reads mail.

---

## Getting reports in

Three ways, all of which end in the same place:

**Drop them in the browser.** Open Import and drag files onto the panel, or
click it. A single report somebody forwarded, a folder of them, or a whole
mailbox export as one zip - including a zip of attachments that are themselves
gzipped, which is what an export usually is. Importing the same thing twice is
safe: reports already stored are recognized and skipped rather than doubled.

**Import a folder or an export on the server.** For an export already on the
machine, or one too large to upload. Same page, at the bottom, or from the
command line, pointed at a folder or at the export zip itself:

    dmarc import --from C:\dmarc-export
    dmarc import --from C:\Downloads\dmarc-export.zip

**Read the mailbox directly**, which is the one that keeps working without
anybody doing anything. See below.

## Collecting reports

Two ways in. The mailbox is the real one.

**From a mailbox**, unattended, all history — see
[`INGEST-SETUP.md`](INGEST-SETUP.md) for the app registration. Start with
`--dry-run`, which parses and reports while writing nothing and moving
nothing, so it is safe against a live mailbox.

**From a folder or a file**, for an archive or files somebody sent you:

```
dmarc import --from C:\dmarc-export
dmarc import --from C:\dmarc-export.zip
```

or the Import page, which runs the same code. Re-importing the same folder is
safe — reports already stored are recognized and skipped — so an interrupted
import is resumed by running it again.

---

## Auditing a zone file

`dmarc check` asks DNS questions. A zone file is the list of what is *in* the
zone, which is a different thing, and it shows what no query can:

    dmarc audit --zone example.com.txt
    dmarc audit --zone example.com.txt --domain example.com   # if the file's header was trimmed off
    dmarc audit --zone example.com.txt --offline              # judge the file alone, ask nothing

Export the file from wherever the domain's DNS is hosted — GoDaddy calls it
**Export zone file**, Cloudflare and Route 53 **Export DNS records** — or use
the paste box at the bottom of the domain page, which runs the same code.

DNS has no query that lists a domain's DKIM selectors, and no authoritative
server hands a stranger the whole zone, so these are only visible in an
export:

- a TXT record that lists includes and ends in `-all` with **no `v=spf1` in
  front of it**: a record somebody wrote, believes is protecting the domain,
  and which every receiver skips over. The tool used to call this "no SPF
  record", which sends an operator to publish a *second* one;
- selectors whose CNAME points at a key the provider stopped serving;
- a key published as `v=DKIM` rather than `v=DKIM1`, or two TXT records at one
  selector — the standard does not say which of several a verifier picks;
- key sizes, across every selector at once rather than one at a time;
- name servers for a provider the domain is no longer delegated to;
- `_report._dmarc` records that authorize nothing, because the version is
  spelled `v=dmarc1` or the domain in the name lost its suffix.

Each finding says whether it came from the file, from live DNS, or from the
reports. A zone export is a snapshot and can disagree with DNS in either
direction — the fault may have been fixed since, or the fix may never have
been published — so a finding the file alone produced says so, and one DNS
confirms says that instead. Where the reports are involved the finding states
the evidence and the window and stops there: a selector that has not signed in
thirty days is a staged key as often as it is a dead one, and this never turns
silence into an instruction to delete anything.

Exit code is 1 when anything breaking was found, so it can gate a pipeline.

---

## Retention: what is kept, and for how long

The schema has assumed a retention window since it was written and nothing
enforced one, so both report tables grew without bound.

    dmarc prune                      # what would go
    dmarc prune --apply
    dmarc prune --aggregate-days 400 --forensic-days 30 --apply

`deploy/install.sh` enables `dmarc-prune.timer` from the first day, weekly. The
window is written into `dmarc-prune.service` where you can read and change it,
rather than left to a default that could move in a later release.

| class | default | why |
|---|---|---|
| aggregate + TLS | **400 days** | thirteen months, so a monthly report always has last year's same month to sit beside; twelve exactly loses it the day it is wanted |
| forensic | **30 days** | these hold **real message headers** — subject lines, message ids, somebody's mail. Deliberately the shortest window here, and the command refuses a policy where it is the longest |

The floor is 7 days for either: receivers report a day or two late, so anything
shorter deletes reports about mail that is still arriving and the domain reads
as quiet.

It is the only thing in this product that deletes a customer's history, so it
counts before it deletes, deletes inside one transaction, and writes what it
removed and under which policy to the audit log. **Domains, clients and
organizations are never touched** — a customer who sent no mail for a year still
exists, only the reports age out.

SQLite does not hand space back to the filesystem on delete; it reuses the
pages, so you reach a steady state rather than unbounded growth. To actually
shrink the file, when there is room for a second copy of it and nothing else is
using it: `sqlite3 dmarc.db VACUUM`.

Turn it on **before** the collector, not after. A window switched on later
deletes a year of history in one run, which is a much bigger thing to approve
than a weekly job that has been quietly ageing reports out all along.

---

## Getting the rows out

    dmarc export --days 7 --failures-only
    dmarc export --format csv --out book.csv
    dmarc export --org acme --domain example.com --days 30

The screens here are opinionated, and that is also their limit. "Every address
that hit these three domains, aligned on SPF only, in a six-hour window" is a
question no fixed view answers, and it should not need a code change to ask. So
rather than grow a query language, this hands the rows over in a shape every
other tool already reads and lets **jq, a spreadsheet, OpenSearch or Splunk be
the query language**.

Rows go to stdout, so it pipes. Everything it says about itself goes to stderr,
so that still works when it does:

    dmarc export --days 7 --failures-only | jq -r .source_ip | sort | uniq -c | sort -rn

`--format csv` for a spreadsheet. Fields beginning `=`, `+`, `-` or `@` are
prefixed with a quote on the way out: these rows carry strings off other
people's mail, and a header that begins `=cmd` is a real thing to hand somebody
as a file they will double-click.

### The columns

One row per `aggregate_records` row, with the reporter and the policy that was
published at the time joined on. Two pairs matter:

| | |
|---|---|
| `dkim_aligned` / `spf_aligned` | what the receiver's DMARC evaluation concluded |
| `dkim_auth` / `spf_auth` | whether the mechanism authenticated at all |

They are separate because a valid signature over the wrong domain is a **pass**
at authentication and a **fail** at alignment. Collapsing them is what makes
DMARC data read as a self-contradiction, and an export that did it would carry
the confusion into whatever you query with.

### Shipping to an index

`--after-id` starts after a row id, and every run prints the one to use next
time. Rows are never rewritten once stored — a reporter resending a report is
refused by the dedup key rather than merged — so "everything above the last id I
shipped" is exactly the new mail:

    dmarc export --after-id "$(cat .watermark)" --out new.ndjson
    # ...ship new.ndjson, then store the id the run printed

For OpenSearch, `_bulk` wants an action line before each document, and giving it
`_id` from the row makes a re-run idempotent rather than doubling the data:

    dmarc export --after-id 41232 \
      | jq -c '{index:{_index:"dmarc",_id:.id}},.' \
      | curl -s -H 'Content-Type: application/x-ndjson' \
             --data-binary @- https://opensearch.example/_bulk

That is the supported way to **run both**: keep the retention window here short
enough that one SQLite file stays quick, and let an index hold the long tail.
See [COMPARISON.md](COMPARISON.md) for what each side is actually better at.

It opens the database read-only, so it is safe to run while the collector has
it.

**`--org` is not optional if it matters.** With no organization named it
exports every one, which is what an operator running it by hand wants and is
the wrong thing to hand a customer. Two organizations on one install can each
manage a domain of the same name.

---

## Can each domain's reports actually reach you?

    dmarc reachability
    dmarc reachability --quiet            # only the domains with something wrong
    dmarc reachability --domain example.com

Both ways this breaks are silent, which is why it needs a standing check rather
than a glance at the DNS.

**The authorization record.** When a client's `rua` points at a mailbox in your
domain, RFC 7489 §7.1 requires *your* domain to publish
`<client>._report._dmarc.<your-domain>` containing `v=DMARC1`. A receiver that
checks and finds nothing **declines to send and tells nobody** — so a broken
customer is indistinguishable from a quiet one. The version is case-sensitive:
`v=dmarc1` authorizes nothing.

**A mailbox nothing collects.** A domain can publish a perfect DMARC record
pointing `rua` at an address the collector does not read. Its DNS looks right,
it produces nothing here, and at `p=reject` it is refusing mail with the
evidence going somewhere nobody looks.

Run it after onboarding a domain — that is when this breaks. The other half of
the check lives in `dmarc audit`: given a zone file and the database, it flags
`_report._dmarc` records authorizing domains you do **not** monitor, which is
how a transposed name is found. `clinet-c.example` beside `client-c.example` reads correctly
in a column of near-identical rows.

---

## Before changing a policy

`dmarc simulate` replays the reports already held against a record you have not
published, and says what it would cost.

    dmarc simulate --domain example.com --policy quarantine
    dmarc simulate --domain example.com --adkim r --aspf r      # what relaxing alignment recovers
    dmarc simulate --domain example.com --days 90

Anything not named keeps what the domain publishes today, so the answer is the
cost of *the change* rather than of the whole record. It exits non-zero when
the change would cost mail, so it can gate a script.

```
  client-d.example
    929 message(s) across 24 day(s) of reports, asked for the last 30;
    9 of them carried a signature the store did not keep, so they are left out
    now      p=quarantine; adkim=r; aspf=r
    proposed p=reject; adkim=r; aspf=r

    costs nothing: no message in the reports held would stop passing
    at p=reject 101 of the 101 failing message(s) would be refused outright
    of the 819 that pass: 124 on DKIM alone, 2 on SPF alone, 693 on both.
```

That last line is what answers "can this domain move to `-all`": mail resting
on DKIM does not care what the SPF all-mechanism says.

Three things it is careful about, because each is a way to produce a confident
wrong answer:

- **Alignment only counts when the mechanism authenticated.** A signature that
  names the domain exactly and did not verify is not rescued by relaxing
  `adkim`. Matching domains by shape instead produced a claim that relaxing
  alignment on one real domain would recover 17 messages; the true answer was
  zero.
- **The baseline is the record in force, not the receivers' verdicts.** `p=`
  decides what happens to failing mail, never whether it fails, so changing it
  alone must cost nothing — and measured the other way it appeared to cost 9.
- **A message the stored row cannot account for is set aside, not counted.** A
  message can carry several DKIM signatures and the store keeps one. Where
  replaying the row disagrees with what the receiver did, the receiver is
  right, the row is excluded from every figure, and the count is stated.

---

## Fixing what it finds

`dmarc check` says what is wrong with a domain's DNS. `dmarc fix` changes it,
and records having done so, which is what the client's monthly report prints
under "what we did".

    dmarc fix --domain example.com                 # dry run: what would change, before and after
    dmarc fix --all                                # the same for every domain
    dmarc fix --domain example.com --apply --reason "Subdomains were left at sp=none"

Without a flag it plans only what is safe on the record's own evidence: a
subdomain policy weaker than the domain's, and an include that resolves to
nothing. Moving the policy is a decision the reports have to justify, so it
is asked for explicitly, and the tool says when they do justify it:

    dmarc fix --domain example.com --policy quarantine --apply --reason "30 days at p=none, everything authenticating"

It refuses to go from `none` to `reject` in one step; `--pct 25` ramps.

Nothing is written without `--apply` and a `--reason`, and the reason is
written for the customer because it goes on their report. Every write is
recorded with what was there before, read from the zone at the moment of
writing:

    dmarc fix --history
    dmarc fix --verify <id>                        # is DNS serving it yet
    dmarc fix --rollback <id> --reason "..."       # put back what was there

To write, the product needs to know which provider holds the zone:

    dmarc dns set --client <slug> --provider cloudflare --zone-id <zone id>
    dmarc dns set --client <slug> --provider azuredns --subscription <id> --resource-group <rg> --zone <zone>
    dmarc dns test --domain example.com
    dmarc dns list

The token is read from `DMARC_DNS_SECRET`, from stdin with `--secret-stdin`,
or at a prompt that does not echo; never from an argument. For Cloudflare use
an API token scoped to `Zone:DNS:Edit` on that one zone, never the Global API
Key. The token goes to the secret store (DPAPI on Windows, an owner-only key
file elsewhere; `dmarc dns list` says which and where) and the database holds
only a reference to it. Without a provider, fixes are planned and shown with
what to publish by hand.

The Fix page in the web app does all of the above with buttons, and Settings
is where providers are added there.

## Scheduling

Daily is enough; receivers send at most once a day per domain.

```powershell
$action = New-ScheduledTaskAction -Execute "C:\dmarc\dmarc.exe" `
    -Argument "ingest --mailbox DMARC@example.com --db C:\dmarc\dmarc.db --tenant ... --client-id ... --cert C:\dmarc\ingest.pfx"
Register-ScheduledTask -TaskName "DMARC ingest" `
    -Action $action -Trigger (New-ScheduledTaskTrigger -Daily -At 6am) `
    -User "NT AUTHORITY\SYSTEM" -RunLevel Highest
```

Monthly, after the month has ended:

```
dmarc report --all --out C:\dmarc\reports --provider "Your Company"
```

That writes one PDF per client — the document you attach to an email. Add
`--html` for the long on-screen version as well, which carries the full
evidence tables and is for reading rather than sending.

`--max` caps messages per ingest run (default 500), so a backlog is worked
through over several runs rather than one long one. Interrupting a run is
safe: it returns what it has already done, and the next run resumes.

---

## Backups

    dmarc backup --to /var/backups/dmarc
    dmarc backup --to /mnt/backup --keep 30

**This is the only thing here that protects the reports.** `dmarc update` and
`rollback.sh` roll the *binary* back; years of a customer's history had
nothing at all, on a product designed to run on one machine.

On a Linux install you do not have to start it: `install.sh` enables
`dmarc-backup.timer` (nightly, 03:20, 14 kept in `/opt/dmarc/backups`) and
takes the first copy during the install, so a machine has a backup before
anybody has put anything in it. That first run is also the one that proves the
thing works *on that machine* — the service account can read the database, the
sandbox lets it write where the unit says, the disk has room. Left to the
timer, all of that is first attempted unattended at 03:20.

Safe to run while the collector is working. The copy comes from SQLite rather
than from the filesystem, so it is a transactionally consistent snapshot — not
whatever the bytes happened to be mid-write. `cp dmarc.db` is not equivalent:
in WAL mode it can catch a torn page and a `-wal` file that does not match it.

### What it checks, and when

**The live database is checked first — before anything is written or removed.**

That ordering is the point. A database that has begun to corrupt still copies,
and the copy verifies, because it is a faithful copy of damaged pages. Fourteen
nights later every backup you hold is a copy of the damage and the last good one
has been pruned away, on schedule, by this very command.

So a source that fails stops the run dead: no copy is written, **nothing is
pruned**, and it exits 74 so the alert fires the same night. Every backup you
already had is still there — which is exactly what you restore from.

Three checks, all on the source:

| | Catches | 17 MB | 313 MB |
|---|---|---|---|
| `integrity_check` | damaged pages, indexes that disagree with their table | 100 ms | 3.8 s |
| `foreign_key_check` | records pointing at reports that are gone — not corruption, data that lost its meaning | 14 ms | 6 ms |
| the copy, re-opened | a copy that did not land correctly | included | included |

`--quick` swaps `integrity_check` for `quick_check` — about nine times faster
(424 ms vs 3.8 s at 313 MB), and it skips precisely the part worth having:
whether each index still agrees with its table. On the numbers above you will
not need it for a very long time.

The counts are printed, because "0 reports" in a log has taught you something
that a silent success would have hidden until a restore.

### How fast

Measured, not estimated. 313 MB is roughly **thirty years** of a
seventeen-domain book at its current rate of 177 records a day:

| | 17 MB (today) | 313 MB |
|---|---|---|
| whole `dmarc backup` run | **56 ms** | **~5 s** |

The nightly job is not something you will notice. It takes a read lock, so a
collector writing at the same moment waits rather than fails — the same retry
that makes two collectors safe.

Retention keeps the newest `--keep` (default 14) and runs **only after a new
copy has verified**, so a failed run never costs you yesterday's. It matches
only files this wrote — a directory you also keep other things in is safe.

On Linux `deploy/install.sh` enables `dmarc-backup.timer` from the first day,
nightly at 03:20, into `/opt/dmarc/backups`.

### Who can read a backup

A backup is a **complete copy of every client's data**. It is written `0600`
into a directory forced to `0700`, so it is readable by the service account and
nobody else — matching the live database rather than whatever the umask
happened to give it.

`dmarc export --out` is the same: `0600`, created that way rather than
chmod'ed afterwards, so the file never exists with rows in it at the wrong
permissions.

Neither is **encrypted at rest**. On AWS that is EBS encryption's job (turn it
on at launch — it cannot be added to a running volume without a snapshot
round-trip), and S3's bucket default encryption for the offsite copy. If you
want the file itself encrypted regardless of where it lands, pipe it through
`age` or `gpg` in `ExecStartPost` before the sync.

### Offsite

A backup on the same machine as the database protects against a bad change.
It does nothing about the failure that actually takes a single-machine install
down, which is the machine. Set `DMARC_BACKUP_S3` in `/etc/dmarc-backup.env`
and the unit syncs the directory after each run:

    DMARC_BACKUP_S3=s3://your-bucket/dmarc

On EC2 the instance role supplies the credentials, so **nothing has to be
stored, rotated or kept out of a config file**. The sync is `aws s3 sync` in
the unit rather than an S3 client inside the product, so swapping it for
rclone, restic or scp is one line you edit rather than a feature you wait for.

A failed upload does not fail the run — the local copy *is* the backup, and a
network problem must not make it look as though nothing was taken.

### Is it still working?

    dmarc health
    dmarc health --backups /opt/dmarc/backups
    dmarc health --quiet            # prints nothing when nothing is wrong

**Everything this looks at fails silently.** A collector whose certificate
expired stops storing reports and says nothing — the pages go on showing the
figures from before it stopped, and those figures look fine. A customer whose
DMARC record somebody else edited stops being reported on, and an empty chart
reads as "no problems" rather than "no data".

Judged on what was **stored**, not on whether a process ran. A collector that
runs perfectly every hour against a mailbox nothing is delivered to succeeds
every time, and a run-history table would call it healthy.

What it checks:

| | |
|---|---|
| Collection, **per organization** | Nothing stored in 36 hours. Per organization because two collectors break independently, and one still working keeps the install-wide figure looking healthy while a whole customer book goes dark. |
| Domains gone quiet | Reports stopped more than 7 days ago while others kept arriving. Not raised when collection itself is broken — then everything is quiet, and saying so 17 times buries the finding that matters. |
| Backups | Only when you name a directory. Left out, nothing is concluded rather than assumed missing. None at all, or a newest copy more than **7 days** old, is backups having stopped. Between 2 and 7 days is one late night and only prints. |
| A name in two organizations | Usually a mistyped `--org` on a collector. Reported, not judged. |

**Exit 1 only when something is actually broken.** A weakness prints and exits
0, because a check that pages every night over one late job is a check
somebody mutes — and then the collector stops into a muted channel.

The two backup thresholds exist because the single one left a hole. "No
backups at all" used to be the only case that failed the unit, and
`install.sh` now takes the first copy during the install — which makes that
case unreachable on a machine anybody installed. The failure a running
install actually develops is the timer stopping and the copies ageing out, and
with one threshold that printed and exited 0. The only case left in practice
was the only case that did not alert.

That exit code is the whole alerting story: it needs no SMTP client, no
webhook signer and no credentials of its own. `deploy/install.sh` enables
`dmarc-health.timer` twice daily, and its `OnFailure=` starts
`dmarc-alert@.service` — which ships doing nothing but writing to the journal,
deliberately, because a unit that pretends to alert is worse than one you had
to write. It carries commented examples for mail, Slack, SNS and
Healthchecks.io; uncomment one, put any secret in `/etc/dmarc-alert.env`, done.

If you already run monitoring, a failed systemd unit is a state Zabbix,
Datadog, the CloudWatch agent and node_exporter all report without being told
how.

### Restoring

A backup is an ordinary SQLite database. Stop the services, put it in place,
and start them — **and delete the `-wal` and `-shm` files first:**

    sudo systemctl stop dmarc-web 'dmarc-ingest*.timer' dmarc-backup.timer

    # THIS LINE IS NOT OPTIONAL
    sudo -u dmarc rm -f /opt/dmarc/data/dmarc.db-wal /opt/dmarc/data/dmarc.db-shm

    sudo -u dmarc cp /opt/dmarc/backups/dmarc-20260922-032000.bak /opt/dmarc/data/dmarc.db
    sudo -u dmarc dmarc init-db --db /opt/dmarc/data/dmarc.db    # applies any newer migrations
    sudo -u dmarc dmarc backup --db /opt/dmarc/data/dmarc.db --to /tmp/verify --keep 1   # integrity-checks it
    sudo systemctl start dmarc-web 'dmarc-ingest*.timer' dmarc-backup.timer

**Why the `rm` matters.** The database runs in WAL mode, so recent writes live
in `dmarc.db-wal` rather than in `dmarc.db`. Copy a backup over `dmarc.db` and
leave the old `-wal` beside it, and SQLite replays that write-ahead log onto
the file you just restored.

Reproduced: a backup taken at 200 rows, restored with the old `-wal` left in
place, opened showing **500 rows — 300 of them written after the backup was
taken.** A clean shutdown checkpoints the WAL away and hides this, which is
exactly why it bites: restores happen after crashes, where it survives.

In the case this section exists for — a database that failed its integrity
check — the damage is as likely to be in the WAL as anywhere, and this lands
it on top of the clean copy.

The `dmarc backup` line before starting the services is not ceremony: it
integrity-checks the restored file and tells you the row counts, so you find
out now rather than when the collector writes to it.

Nothing is lost in the gap: reports stay in the mailbox until a run stores
them, so the next collection picks up whatever arrived meanwhile.

---

## Where things live

| | |
|---|---|
| database | wherever `--db` / `Database:Path` says. One file, plus `-wal` and `-shm` while it is open. |
| reports | `--out`, default `reports/` |
| certificate | not in the repository. The ingest one needs its private key. |

The database is the only state. Back it up and everything else is
reproducible; lose it and the reports are gone, because receivers do not
re-send.

---

## Transport security: MTA-STS and TLS-RPT

Two records that say mail to a domain must travel over a verified, encrypted
connection. Publish them in this order, because the second needs what the
first produces.

**TLS-RPT first.** It asks receivers to report failed or downgraded
connections and changes nothing about delivery, so it is safe on any domain:

    dmarc fix --domain example.com --tls-rpt-to tls@nrgtechservices.com --apply --reason "..."

**MTA-STS second**, and it is two halves that must agree. A TXT record
announces a policy id; the policy itself is a file served over HTTPS at
`mta-sts.<domain>/.well-known/mta-sts.txt`. Only the record is DNS, so the
web app serves the file:

    dmarc mta-sts set --domain example.com          # mail servers from its MX records
    # point mta-sts.example.com at the host running the web app (a CNAME)
    dmarc mta-sts check --domain example.com        # fetch it back, as a sender would
    dmarc fix --domain example.com --apply --reason "..."   # announce it

A policy starts in `testing`, where a sender that cannot connect securely
reports it and delivers anyway. Moving to `enforce` is the dangerous step and
works like advancing a DMARC policy: `dmarc fix` will say what blocks it -
whether TLS reports are arriving, whether any connections are failing, and
whether the policy covers every mail server the domain publishes.

Two things about enforce worth knowing before you get there. A sender that
reaches a mail server the policy does not list does not deliver and does not
fall back. And senders cache the policy for its `max_age`, a week by default,
so a mistake outlasts the fix for it. That is why `--mode enforce` refuses
without `--i-have-checked`.

## Upgrading

`dmarc version` says what a build is and which database schema it expects.

`dmarc init-db` against an existing database brings its schema up to date and
says what it applied. Run it after installing a new build, before starting the
service; it is safe to run when there is nothing to do.

On a deployed server, `deploy/update.sh` does the whole sequence - back up,
swap, migrate, start, verify, and put the old one back if it does not come
up. See `DEPLOYING.md` for how releases and development are kept apart.

## Putting it on a server

`DEPLOYING.md` covers that end to end for Ubuntu and Amazon Linux: which
machine, what it costs, `deploy/install.sh`, the proxy and certificate, Entra
sign-in, ingest on a timer, backups, and the checklist of things that must be
true before it is reachable by anybody else.

The one thing to know before reading it: until Entra sign-in is configured
this app has no login at all, and it protects itself by refusing to serve
anything but the machine it runs on. Putting a reverse proxy in front does
not change that - a proxied request is refused outright, because being proxied
is itself evidence that somebody else can reach it.

## Known unfinished

[`OPEN-ISSUES.md`](OPEN-ISSUES.md) is the honest list. The one worth knowing
before you rely on this: **the Graph collection path has never run against a
real mailbox.** Everything else has been exercised against 1,687 real reports
across ten domains; that has not.
