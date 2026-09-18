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
dmarc import --from C:\some-folder-of-reports
dmarc client add    --name "Acme Corp"
dmarc client assign --domain acme.com --client acme-corp
dmarc report --client acme-corp --provider "Your Company"
```

`dmarc explain <file>` reads a single report and says what it means in plain
English, with no database at all. It is the fastest way to check a report
somebody has just forwarded you.

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
safe: reports already stored are recognised and skipped rather than doubled.

**Import a folder on the server.** For an export already on the machine, or
one too large to upload. Same page, at the bottom, or from the command line:

    dmarc import --from C:\dmarc-export

**Read the mailbox directly**, which is the one that keeps working without
anybody doing anything. See below.

## Collecting reports

Two ways in. The mailbox is the real one.

**From a mailbox**, unattended, all history — see
[`INGEST-SETUP.md`](INGEST-SETUP.md) for the app registration. Start with
`--dry-run`, which parses and reports while writing nothing and moving
nothing, so it is safe against a live mailbox.

**From a folder**, for an archive or files somebody sent you:

```
dmarc import --from C:\dmarc-export
```

or the Import page, which runs the same code. Re-importing the same folder is
safe — reports already stored are recognised and skipped — so an interrupted
import is resumed by running it again.

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

`dmarc init-db` against an existing database brings its schema up to date and
says what it applied. Run it after installing a new build, before starting the
service; it is safe to run when there is nothing to do.

## Putting it on a server

`DEPLOYING.md` covers that end to end: which machine, what it costs, the proxy
and certificate, Entra sign-in, ingest on a timer, backups, and the checklist
of things that must be true before it is reachable by anybody else.

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
