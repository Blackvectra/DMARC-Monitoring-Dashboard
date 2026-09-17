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

Entra admin centre → App registrations → New registration.

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

Create one — on Windows:

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

`--dry-run` parses everything and reports what it found, writing nothing and
moving nothing. Run it against the live mailbox as many times as you like.

What to check in the output:

- **Messages read** roughly matches what is in the mailbox. A much smaller
  number means folders are not being walked.
- **Every client domain appears.** The domains the Outlook export truncated —
  `mortonnd.gov`, `redriverrc.com`, `mcleanelectric.com` — should show
  current data here. If they do not, the reports genuinely are not arriving
  and that is a finding rather than a bug.
- **Errors are named, not counted.** Anything unreadable is listed.

Then drop `--dry-run`. The first real run stores everything and moves each
message into the processed folder. Messages are filed only after their reports
are stored, so an interruption re-reads rather than loses, and the duplicate
check makes the second read harmless.

---

## Scheduling it

Daily is enough — receivers send at most once a day per domain, most of them
overnight.

```powershell
$action = New-ScheduledTaskAction -Execute "C:\dmarc\dmarc.exe" `
    -Argument "ingest --mailbox DMARC@nrgtechservices.com --db C:\dmarc\dmarc.db ..." 
$trigger = New-ScheduledTaskTrigger -Daily -At 6am
Register-ScheduledTask -TaskName "DMARC ingest" -Action $action -Trigger $trigger `
    -User "NT AUTHORITY\SYSTEM" -RunLevel Highest
```

`--max` caps messages per run (default 500) so a backlog is worked through
over several runs rather than one long one. Ctrl+C and a scheduler timeout are
both handled: the run returns what it has already done and the next one
resumes.

---

## Known untested

Nothing in the Graph path has run against a real mailbox. The parts most
likely to behave differently from the test fake:

- **Throttling.** Graph returns 429 with `Retry-After`; the handler honours it
  in tests, and a mailbox with thousands of messages is where that is first
  exercised for real.
- **Folder names containing a backslash.** The live mailbox has folders named
  `DMARC\bmcedc.com`. Graph addresses folders by id so this should not matter,
  but it has not been proved.
- **Attachment shapes.** Large or unusual attachments come back from Graph
  differently from the way the fake produces them.

`--dry-run` exercises all of this without writing or moving anything, which is
why it is worth running more than once before the first real pass.
