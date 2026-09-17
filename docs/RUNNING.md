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

## Known unfinished

[`OPEN-ISSUES.md`](OPEN-ISSUES.md) is the honest list. The one worth knowing
before you rely on this: **the Graph collection path has never run against a
real mailbox.** Everything else has been exercised against 1,687 real reports
across ten domains; that has not.
