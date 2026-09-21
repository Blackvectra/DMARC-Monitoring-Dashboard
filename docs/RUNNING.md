# Running it

Two pieces. They share a SQLite file and nothing else.

- **`dmarc`** — collects reports and writes client reports. One binary, no
  .NET install, no checkout. Runs on a schedule.
- **The web app** — the screens. Reads the database the CLI writes, and
  writes only when onboarding a domain or importing a folder.

Neither needs the other running. The CLI works with no web app; the web app
shows an empty state until something has been collected.

---

## Quickest possible start

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
how a transposed name is found. `ndgaa.com` beside `ndgga.com` reads correctly
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
  ndaco.org
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

`--max` caps messages per ingest run (default 500), so a backlog is worked
through over several runs rather than one long one. Interrupting a run is
safe: it returns what it has already done, and the next run resumes.

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
