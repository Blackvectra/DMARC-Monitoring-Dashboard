# Setting up ingest

How `dmarc ingest` gets permission to read the reporting mailbox, and how to
prove it works before pointing it at anything live.

This replaces the Outlook exporter. The exporter needs a desktop with Outlook
open and a person to run it; ingest runs unattended against Microsoft Graph and
reads whatever is in the mailbox, including history the exporter never reached.

---

## What it needs, and why each part

**An app registration with `Mail.ReadWrite` as an APPLICATION permission.**
Application rather than delegated because this runs on a schedule with nobody
signed in. `ReadWrite` rather than `Read` because ingest moves each message
into a processed folder once its reports are stored — that is what stops the
same report being read every night forever.

**A certificate rather than a client secret.** A secret expires, usually
silently, and the first sign is a month of missing reports. A certificate
expires too, but it is one file the deployment already has to manage rather
than a string pasted into configuration.

**An application access policy.** This is the part not to skip.
`Mail.ReadWrite` as an application permission grants access to **every mailbox
in the tenant** by default. The policy restricts it to the one shared mailbox,
so a mistake or a stolen certificate reaches the DMARC reports and nothing
else. Without it, this app registration can read the CEO's mail.

---

## Steps

### 1. Register the application

Entra admin center → App registrations → New registration.

- Name: something that says what it is, e.g. `DMARC Monitor ingest`
- Supported account types: single tenant
- Redirect URI: none. It never signs a person in.

Note the **Application (client) ID** and **Directory (tenant) ID**.

### 2. Grant the permission

API permissions → Add a permission → Microsoft Graph → **Application
permissions** → `Mail.ReadWrite`.

Then **Grant admin consent**. An application permission does nothing until an
administrator consents; without this the first run fails with an
authorization error that does not say why.

Add nothing else. `Mail.Read` is not enough (the move fails) and anything
broader is a larger blast radius for no gain.

### 3. Upload a certificate

The deployment scripts make one for you and print the file to upload:

```bash
sudo ./deploy/bootstrap.sh --host <your host> --make-ingest-cert          # Linux
.\bootstrap.ps1 -HostName <your host> -MakeIngestCert                     # Windows
```

The private half lands where the collector runs (`/opt/dmarc/data/ingest.pfx`
or `C:\dmarc\data\ingest.pfx`, readable by the service account only) and its
password goes where the collector reads it. Upload the printed `.cer`.

To make one by hand instead — on Windows:

```powershell
$cert = New-SelfSignedCertificate `
    -Subject "CN=DMARC Monitor ingest" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -NotAfter (Get-Date).AddYears(2)

# Public half, to upload to Entra
Export-Certificate -Cert $cert -FilePath dmarc-ingest.cer

# Private half, for the machine that runs ingest. Keep it out of the repo.
$password = Read-Host -AsSecureString "Password for the .pfx"
Export-PfxCertificate -Cert $cert -FilePath dmarc-ingest.pfx -Password $password
```

Upload `dmarc-ingest.cer` under Certificates & secrets → Certificates.

Put a calendar reminder a month before `NotAfter`. An expired certificate
looks exactly like a mailbox that stopped receiving reports.

### 4. Restrict it to the one mailbox

**Do this before the first run.** Until it is in place the registration can
read every mailbox in the tenant.

```powershell
Connect-ExchangeOnline

New-DistributionGroup -Name "DMARC Ingest Scope" `
    -Alias dmarc-ingest-scope -Type Security `
    -Members "DMARC@nrgtechservices.com"

New-ApplicationAccessPolicy `
    -AppId "<application client id>" `
    -PolicyScopeGroupId "dmarc-ingest-scope@nrgtechservices.com" `
    -AccessRight RestrictAccess `
    -Description "DMARC Monitor reads only the reporting mailbox"
```

Then prove it both ways:

```powershell
# Should say Granted
Test-ApplicationAccessPolicy -Identity "DMARC@nrgtechservices.com" -AppId "<id>"

# Should say Denied. If it says Granted, the policy is not doing its job.
Test-ApplicationAccessPolicy -Identity "<some other mailbox>" -AppId "<id>"
```

The second check is the one worth running. A policy that exists but does not
apply reads as success everywhere except where it matters.

Policies can take a few minutes to take effect.

---

## First run

```
dmarc ingest ^
  --mailbox DMARC@nrgtechservices.com ^
  --tenant <tenant id> ^
  --client-id <application id> ^
  --cert dmarc-ingest.pfx ^
  --cert-password <password> ^
  --dry-run
```

On a machine set up by the deployment scripts the same values are already in
the environment file (`/etc/dmarc-ingest.env`) or `C:\dmarc\ingest.cmd`, and
the dry run is the command `bootstrap` printed, or `C:\dmarc\ingest.cmd --dry-run`.

Reports are attributed to a domain by the address they were sent to. With
one shared mailbox that every domain's `rua` points at - the usual shape -
nothing more is needed: the mailbox itself is that address, and the run says
so on its second line. If the `rua` address is not literally the mailbox's
own address - an alias, a distribution group that delivers into it, or you
gave `--mailbox` the account's UPN - pass the address in the `rua` tag as
`--fallback` (or set `DMARC_FALLBACK_ADDRESS`). If per-domain addresses such as
`client.com@rua.example.com` are in use, pass `--reporting-domain
rua.example.com` (or set `DMARC_REPORTING_DOMAIN`).

Getting this wrong is safe. A genuine report sent to an address the collector
does not recognize is counted as **not attributed**, listed with the address
it was sent to, and left in the mailbox rather than filed away; when none at
all could be attributed the run exits 64 and says which address to set. Fix
the address and the next run ingests them.

With more than one organization on the install, each organization's mailbox
gets its own collector run with `--org <slug>` (or `DMARC_ORGANIZATION` in the
environment file). That decides where a domain nobody has seen before is
filed; a domain already known keeps its organization whichever mailbox its
reports arrive in.

`--dry-run` parses everything and reports what it found, writing nothing and
moving nothing. Run it against the live mailbox as many times as you like.

What to check in the output:

- **Messages read** roughly matches what is in the mailbox. A much smaller
  number means folders are not being walked: compare `folders read` with the
  folders your mail rules file reports into, and see
  [Which folders it reads](#which-folders-it-reads).
- **Every client domain appears.** The domains the Outlook export truncated —
  `acme.example`, `client-e.example`, `client-f.example` — should show
  current data here. If they do not, the reports genuinely are not arriving
  and that is a finding rather than a bug.
- **Errors are named, not counted.** Anything unreadable is listed. So is a
  report that could not be stored: its message is left where it was for the
  next run, `reports ingested` says how many of them were stored and how many
  were not, and the run exits 1.

Then drop `--dry-run`. The first real run stores everything and moves each
message into the processed folder. Messages are filed only after their reports
are stored, so an interruption re-reads rather than loses, and the duplicate
check makes the second read harmless.

---

## Which folders it reads

With nothing configured: Inbox, and the folders directly inside it, which is
where a mail rule sorting reports by domain usually puts them.

If your rules file reports somewhere else, name the folders to read instead,
one `--folder` for each:

```
dmarc ingest --mailbox DMARC@nrgtechservices.com --folder "DMARC\client-a.example" --folder "DMARC\client-b.example" --folder Inbox --dry-run
```

- **Naming folders replaces the default.** Inbox is read only when it is one
  of the names, as above.
- **Each named folder is read with the folders directly inside it**, the way
  Inbox is.
- **A name is a folder at the top of the folder list**, at the same level as
  Inbox, matched by its whole name, ignoring case. A backslash is part of the
  name, not a path: `DMARC\client-a.example` is one folder called exactly
  that, not `client-a.example` inside `DMARC`. To read `client-a.example`
  inside `DMARC`, name `DMARC`.
- **A name that matches no folder is reported and skipped, never created.**
  The other folders are still read, and the run exits 1. A dry run says so
  too.
- **The folders ingest files into** — `DMARC-Processed`, `DMARC-Unrecognized`
  and `DMARC-Quarantine` — are never read, even when named: everything in them
  has been dealt with already.

For the scheduled run, set `DMARC_FOLDERS` in the environment file, with the
names separated by semicolons. **Put the value in single quotes.** systemd, and
a shell reading the same file, treat an unquoted backslash as an escape and
drop it, and `DMARC\client-a.example` then arrives as `DMARCclient-a.example`,
which matches nothing:

```bash
DMARC_FOLDERS='DMARC\client-a.example;DMARC\client-b.example;Inbox'
```

The same goes for `--folder` typed into a shell: put the name in double quotes,
as above, which keeps the backslash in bash, PowerShell and cmd alike. With
more than one mailbox, each instance's own `/etc/dmarc-ingest-<instance>.env`
carries its own `DMARC_FOLDERS`.

`bootstrap.sh` writes the line into `/etc/dmarc-ingest.env` for you, quoted,
from one `--folder` for each name:

```bash
sudo ./deploy/bootstrap.sh --host <your host> --folder "DMARC\client-a.example" --folder "DMARC\client-b.example" --folder Inbox
```

On Windows, `bootstrap.ps1` writes it into `C:\dmarc\ingest.cmd` from
`-Folders`:

```powershell
.\bootstrap.ps1 -HostName <your host> -Folders "DMARC\client-a.example", "DMARC\client-b.example", Inbox
```

Or add the line to `C:\dmarc\ingest.cmd` yourself, above the line that runs
`dmarc.exe`. A backslash needs no quoting there:

```
set "DMARC_FOLDERS=DMARC\client-a.example;DMARC\client-b.example;Inbox"
```

Running `bootstrap.ps1` again keeps the line, however it got there, and
changes it only when given `-Folders`. A `DMARC_FOLDERS` set as a system
environment variable still works, but only while `ingest.cmd` has no line of
its own.

A `--folder` on the command line wins over `DMARC_FOLDERS`. Either way, the run
prints the folders it was told to read before it starts, and `folders read` at
the end lists every folder it actually read, so a folder that was named but
never reached is plain from the output.

---

## Scheduling it

The deployment scripts schedule it once they know the mailbox, the tenant,
the application id and the certificate: hourly, as `dmarc-ingest.timer` on
Linux (`docs/DEPLOYING.md` step 6) and as the Task Scheduler task
`DMARC ingest` on Windows, running as the service account. Hourly is more
than enough; receivers send at most once a day per domain, most of them
overnight, and a run that finds nothing costs nothing.

By hand on Windows, if you are not using `bootstrap.ps1`:

```powershell
$action = New-ScheduledTaskAction -Execute "C:\dmarc\bin\dmarc.exe" `
    -Argument "ingest --mailbox DMARC@nrgtechservices.com --db C:\dmarc\data\dmarc.db --cert C:\dmarc\data\ingest.pfx --tenant <id> --client-id <id>"
$trigger = New-ScheduledTaskTrigger -Daily -At 6am
Register-ScheduledTask -TaskName "DMARC ingest" -Action $action -Trigger $trigger `
    -User "NT AUTHORITY\SYSTEM" -RunLevel Highest
```

`--max` caps messages per run (default 500) so a backlog is worked through
over several runs rather than one long one. Ctrl+C and a scheduler timeout are
both handled: the run returns what it has already done and the next one
resumes.

---

## More than one mailbox

An MSP collecting for more than one organization needs one collector per
mailbox, because **a domain belongs to an organization**. A mailbox collected
under the wrong one does not file into the right customer's domain — it makes
a *second copy* of that domain under the collecting organization, and says
nothing while the real one quietly stops growing.

On Linux that is the templated unit, one instance per mailbox. The instance
name picks the environment file and nothing else, so name it after the
organization:

```bash
# one env file per mailbox
sudo cp /etc/dmarc-ingest.env /etc/dmarc-ingest-acme.env
sudo chmod 0600 /etc/dmarc-ingest-acme.env
```

Then in each copy set the two lines that differ:

```bash
DMARC_MAILBOX=dmarc@acme-managed.example
DMARC_ORGANIZATION=acme          # must match a slug from: dmarc org list
```

```bash
sudo systemctl enable --now dmarc-ingest@acme.timer
sudo systemctl enable --now dmarc-ingest@beta.timer

# and turn off the single-mailbox one, so nothing is collected twice
sudo systemctl disable --now dmarc-ingest.timer
```

`--org` is passed explicitly by the unit rather than left to the environment.
An instance whose env file is missing `DMARC_ORGANIZATION` fails loudly
instead of quietly collecting a customer's mailbox into `local`.

**Two collectors writing at once is safe.** Their timers are independent and
both write to the same SQLite file, which is in WAL mode with a retry on a
busy database — concurrent runs serialize rather than failing. Verified with
two writers against one file: 400 of 400 rows committed, none lost.

To check the result, and to catch a mistyped `--org`:

```bash
dmarc org list
dmarc reachability          # flags a domain name held by more than one organization
```

The single-mailbox `dmarc-ingest.service` still exists and still reads
`/etc/dmarc-ingest.env`, so an install already using it keeps working. Use one
shape or the other, not both against the same mailbox.

---

## Keeping the mailbox from filling up

Every receiver sends a report for every domain every day, and by default a
processed message is filed into `DMARC-Processed` — the same mailbox, the same
quota. On any real book of domains the mailbox fills.

```
dmarc ingest --mailbox dmarc@example.com --delete soft
dmarc ingest --mailbox dmarc@example.com --delete permanent
```

or, for the scheduled run, put it in `/etc/dmarc-ingest.env` so the unit file
needs no editing:

```
DMARC_DELETE=permanent
```

| mode | where the message goes | quota |
|---|---|---|
| `soft` | Deleted Items — a person can drag it back | **still used**, until a retention policy clears the folder |
| `permanent` | Recoverable Items — recoverable for the tenant's deleted-item retention period | **freed**; Recoverable Items has its own quota |

If the mailbox filling up is the problem you are solving, `permanent` is the
one that solves it. `soft` empties the inbox and frees nothing.

**Only mail whose reports are already in the database is ever deleted**, and
that ordering is enforced in the same place as the move: a message is deleted
after its reports are stored, never before. Three kinds of mail are always
kept, whatever this is set to:

- **not a report, or one this version cannot parse** — it is the only copy of
  the evidence needed to teach the parser to read it, and a report nobody has
  written a parser for looks exactly like junk;
- **quarantined** — the delivery address and the report disagree about the
  domain, which is the shape of an injected report;
- **not attributed** — a genuine report delivered somewhere this deployment
  does not recognize, which is a configuration mistake to correct and re-run.

Duplicates *are* deleted: a re-sent report is by definition already stored, and
re-sends are most of what fills a mailbox.

`--dry-run` deletes nothing, so run it first.

---

## Known untested

Nothing in the Graph path has run against a real mailbox. The parts most
likely to behave differently from the test fake:

- **Throttling.** Graph returns 429 with `Retry-After`; the handler honours it
  in tests, and a mailbox with thousands of messages is where that is first
  exercised for real.
- **Folder names containing a backslash.** The live mailbox has folders named
  `DMARC\client-a.example`. A named folder is found by listing the folders at
  the top of the mailbox and comparing names in the collector itself, so no
  filter on the server has to parse the backslash, and it is read by id from
  then on. That is unit-tested against a stub of Graph, and has not yet run
  against the mailbox.
- **Attachment shapes.** Large or unusual attachments come back from Graph
  differently from the way the fake produces them.

`--dry-run` exercises all of this without writing or moving anything, which is
why it is worth running more than once before the first real pass.
