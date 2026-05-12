# DMARC Monitor

Self-hosted DMARC monitoring with feature parity to paid tools (DMARCian, Valimail, Sendmarc). Polls a shared mailbox via Microsoft Graph every 30 minutes. WPF dashboard with domain sidebar, compliance scoring, and per-domain views.

**No hardcoded values. No config files. No client secrets.** Certificate-based app-only auth. All configuration through the GUI, persisted to Windows Registry (DPAPI-encrypted for secrets).

---

## What This Monitors

**Report ingestion**
- DMARC aggregate (rua) — RFC 7489 XML, with override reasons + subdomain analysis
- DMARC forensic (ruf) — RFC 6591 MIME/ARF
- TLS-RPT — RFC 8460 JSON

**Source analysis** (DMARCian "Senders" parity)
- Every sending source with compliance status
- New sender first-seen detection + alerting
- ESP classification (16 known providers — Google, Microsoft, SendGrid, Mailchimp, Mailgun, SES, Postmark, etc.)
- IP geolocation (ipinfo.io HTTPS, PS7 parallel)
- Volume anomaly detection (rolling 7-sample baseline)
- Cousin domain detection (Levenshtein ≤ 2)
- Reporting org coverage tracker (Google/Microsoft/Yahoo/Apple)

**DNS health**
- DMARC record audit with policy gap analysis (`pct<100`, `sp=none`, `adkim/aspf` relaxed)
- SPF lookup depth (RFC 7208 limit: 10), mechanism count
- SPF recursive chain visualization with per-node lookup counts
- DKIM key inspector (30+ common selectors, key length, algorithm)
- MTA-STS policy monitoring (RFC 8461)
- BIMI record validation with VMC check

**Analytics**
- Compliance score per domain (0-100, DMARCian-style)
- Enforcement recommendation engine (14-day data analysis)
- DMARC policy progression tracker (none → quarantine → reject)
- Per-domain alert thresholds

**Alerting**
- Teams webhook (MessageCard)
- Email via Graph sendMail
- New sender, volume anomaly, cousin domain, DNS health, MTA-STS change, cert expiry (60-day warning)
- Daily HTML digest email with enforcement recommendations

---

## Files

```
src/
├── Install-DMARCMonitor.ps1    # Automated installer — Entra + cert + EXO + registry (run this first)
├── Start-DMARCDashboard.ps1        # WPF dashboard — daily use
├── Invoke-DMARCReporter.ps1        # Engine — called by dashboard or scheduled task
├── Invoke-SPFInspector.ps1         # SPF chain + DKIM key inspector (called by dashboard)
└── Invoke-HTMLReportGenerator.ps1  # Client-facing HTML reports (optional)
```

---

## Prerequisites

- Windows 10/11 or Windows Server 2019+
- PowerShell 7 recommended (`winget install Microsoft.PowerShell`) — runs on 5.1 but auto-relaunches in PS7 if available
- `Microsoft.Graph.Authentication` module — installed automatically via dashboard banner on first launch
- Shared mailbox for report ingestion (e.g. `dmarc@yourdomain.com`)

---

## Setup

You have two paths. Pick one.

| Path | When to use |
|---|---|
| **A — Automated installer** | First time setup, want it running fast, comfortable with running a PowerShell script that creates Entra resources |
| **B — Manual setup** | You want to see every step, need to delegate parts to a different admin (e.g. you can do Entra but not Exchange), or troubleshooting a partial install |

---

### Path A — Automated Installer (recommended, ~10 minutes)

The `Install-DMARCMonitor.ps1` script does all the Entra + EXO + cert + registry work for you. You sign in twice (Entra and Exchange), answer a few prompts, and the dashboard launches at the end.

**Prerequisites (one-time)**

- Your account has either **Global Admin** or both **Application Administrator** + **Exchange Administrator** roles
- The DMARC mailbox already exists in Exchange (shared mailbox is fine)
- You're running on the machine that will host the engine (DPAPI binds to this machine)

**Steps**

1. **Clone or copy the repo to the machine**
   ```powershell
   git clone https://github.com/<your-org>/DMARC-Monitoring-Dashboard C:\Tools\DMARC-Monitoring-Dashboard
   ```
   Or download the ZIP and extract to `C:\Tools\DMARC-Monitoring-Dashboard`.

2. **Open PowerShell as Administrator**
   Right-click PowerShell → Run as administrator. Required for LocalMachine cert store.

3. **Run the installer**
   ```powershell
   cd C:\Tools\DMARC-Monitoring-Dashboard\src
   pwsh -ExecutionPolicy Bypass -File .\Install-DMARCMonitor.ps1
   ```
   If you don't have PowerShell 7 yet:
   ```powershell
   winget install Microsoft.PowerShell
   ```
   Then re-run from a fresh terminal.

4. **Answer the prompts**
   - Mailbox address: `dmarc@yourdomain.com`
   - Working directory: press Enter to accept `C:\ProgramData\DMARCMonitor\DMARC`, or type your own
   - Confirm: `Y`

5. **Watch the installer work**
   You'll see it:
   - Install Graph and EXO modules
   - Generate the certificate
   - Prompt you to sign in to Microsoft Graph — **use Application Admin or Global Admin account**
   - Create the Entra app registration with required permissions
   - Upload the certificate
   - Grant admin consent
   - Prompt you to sign in to Exchange Online — **use Exchange Admin or Global Admin account**
   - Apply the mailbox access policy
   - Write registry settings (DPAPI-encrypted for secrets)
   - Test cert auth by querying the mailbox
   - Launch the dashboard

6. **Dashboard opens — click "Run Now"**
   First run drains your DMARC backlog. With a heavy backlog, this can take 10-30 minutes. Don't kill it; it paginates through 50 messages at a time.

7. **When the first run completes, click "Schedule"**
   Creates the every-30-minutes scheduled task. From here on the engine runs autonomously.

8. **Done.** Check the dashboard tomorrow morning. Daily digest is off by default — enable in Settings if you want a morning email summary.

**Re-running the installer is safe.** It detects existing certs, app registrations, and policies and offers to reuse them rather than duplicating.

---

### Path B — Manual Setup (full control, ~20 minutes)

If you want to do each piece yourself, or split the work across admins.

#### Step 1 — Create the Entra App Registration

1. Sign in to **entra.microsoft.com** as Application Administrator or Global Admin
2. **Identity → Applications → App registrations → New registration**
3. Fill in:
   - **Name:** `DMARCMonitor`
   - **Supported account types:** Single tenant
   - **Redirect URI:** leave blank
4. Click **Register**
5. On the Overview page, copy these two values to a scratchpad:
   - **Application (client) ID**
   - **Directory (tenant) ID**

#### Step 2 — Add API Permissions

1. Still in your new app → **API permissions** in the left nav
2. **Add a permission → Microsoft Graph → Application permissions**
3. Search and check:
   - `Mail.ReadWrite`
   - `Mail.Send`
4. Click **Add permissions**
5. Click **Grant admin consent for [your tenant]** → **Yes**
6. Verify both rows show green "Granted for [tenant]" status

> Do **not** create a client secret. We use certificate-based auth.

#### Step 3 — Scope the Mailbox in Exchange Online

Without this, the app's `Mail.ReadWrite` applies to every mailbox in the tenant. This policy restricts it to just the DMARC mailbox.

1. Open PowerShell as your normal user
2. Install and connect:
   ```powershell
   Install-Module ExchangeOnlineManagement -Scope CurrentUser
   Connect-ExchangeOnline
   ```
3. Apply the policy (replace the AppId with your Client ID from Step 1):
   ```powershell
   New-ApplicationAccessPolicy `
       -AppId "<YOUR-CLIENT-ID>" `
       -PolicyScopeGroupId "dmarc@yourdomain.com" `
       -AccessRight RestrictAccess `
       -Description "Restrict DMARC Monitor to dmarc mailbox only"
   ```
4. Verify:
   ```powershell
   Test-ApplicationAccessPolicy -AppId "<YOUR-CLIENT-ID>" -Identity "dmarc@yourdomain.com"
   # AccessCheckResult: Granted

   Test-ApplicationAccessPolicy -AppId "<YOUR-CLIENT-ID>" -Identity "someone-else@yourdomain.com"
   # AccessCheckResult: Denied
   ```
5. `Disconnect-ExchangeOnline -Confirm:$false`

#### Step 4 — Clone the Repo

```powershell
git clone https://github.com/<your-org>/DMARC-Monitoring-Dashboard C:\Tools\DMARC-Monitoring-Dashboard
```

Or download the ZIP and extract.

#### Step 5 — Launch the Dashboard

```powershell
cd C:\Tools\DMARC-Monitoring-Dashboard\src
pwsh -STA -ExecutionPolicy Bypass -File .\Start-DMARCDashboard.ps1
```

If PowerShell 7 isn't installed:
```powershell
winget install Microsoft.PowerShell
```

On first launch:
- If `Microsoft.Graph.Authentication` is missing, a yellow banner appears with an **Install Now** button. Click it.
- Settings dialog opens automatically.

#### Step 6 — Generate the Certificate

In the Settings dialog:

1. Choose **Cert Store**:
   - **LocalMachine** — survives logout, requires admin. Recommended for scheduled task.
   - **CurrentUser** — no admin needed, tied to your profile. Fine for testing.
2. Click **Generate Certificate + Export .cer**
3. Save dialog appears → save the `.cer` to your Desktop (or anywhere — it's just the public key)
4. The thumbprint auto-populates. Status shows:
   - Subject: `CN=DMARCMonitor-<MACHINENAME>`
   - Algorithm: SHA-512 / RSA-2048
   - Private key: NonExportable
   - Validity: 2 years

#### Step 7 — Upload the .cer to Entra

1. Back in **Entra portal → App registrations → DMARCMonitor**
2. **Certificates & secrets → Certificates → Upload certificate**
3. Browse to the `.cer` you saved → **Add**
4. Verify the thumbprint matches what's in your dashboard Settings field

#### Step 8 — Fill in the Rest of Settings

| Field | Value |
|---|---|
| **Tenant ID** | Directory ID from Entra Overview (paste from scratchpad) |
| **Client ID** | Application ID from Entra Overview (paste from scratchpad) |
| **Mailbox** | `dmarc@yourdomain.com` |
| **Working Directory** | Any path with write access — `C:\ProgramData\DMARCMonitor\DMARC` is a good default |
| **Retention Days** | `7` |
| **Source Folder** | `Inbox` |

**Phase 2-5 toggles** (recommended starting set):
- ☑ Enable IP geolocation
- ☑ Enable failure rate alerts (set threshold, email)
- ☑ New sender alerts
- ☑ Volume anomaly alerts
- ☑ DNS health checks
- ☑ Cousin domain detection
- ☑ Track reporting org coverage
- ☑ MTA-STS monitoring
- ☑ BIMI validation
- ☑ DKIM signing domain tracking
- ☐ Daily digest (turn on later after you've verified things work)

Click **Save Settings**.

#### Step 9 — First Run

Click **Run Now** in the toolbar. Watch the run log panel at the bottom.

What you should see:
```
[INFO] Polling: Inbox
[INFO] Found N messages with attachments
[INFO] Downloaded: report.xml.gz (X.X KB)
[SUCCESS] RUA: <filename> | domain.com | N records
...
[SUCCESS] DMARC CSV: dmarc_aggregate_YYYY-MM-DD.csv — N records
[SUCCESS] Done | RUA:N RUF:N TLS:N | Exit:0
```

If you see `Exit:2`, that's a Graph auth failure — the cert isn't matched to the app in Entra. Re-verify Step 7.

If you see `Exit:3`, that's a mailbox connection failure — re-verify Step 3.

If you see `Exit:4`, no new reports yet — that's fine, it'll catch them next run.

#### Step 10 — Schedule the Task

Click **Schedule** in the toolbar. Confirm the prompt.

A task is created at `\DMARCMonitor\DMARC Monitor` running every 30 minutes, starting in 2 minutes from now.

Verify:
```powershell
Get-ScheduledTask -TaskName "DMARC Monitor" -TaskPath "\DMARCMonitor\"
```

Done. The engine now runs autonomously every 30 minutes.

---

### Verifying It's Working

After 24-48 hours of running, check the dashboard:

1. **Overview tab** — Should show a compliance score, pass rate, and policy badge for each domain in the sidebar
2. **DMARC tab** — Aggregate records visible, override reasons populated
3. **Sources tab** — Every sending IP for your domains with first/last seen
4. **DNS Health tab** — All known domains audited, issues flagged
5. **Trends tab** — Multi-day pass rate chart populated
6. **Protocol tab** — MTA-STS, BIMI, DKIM status per domain

If any tab is empty after 48 hours, check:
- Event Log → Application → Source: DMARCMonitor — event 1000 should fire every 30 minutes
- `<WorkingDir>\Logs\DMARCReporter_YYYY-MM.log` — full run history

---

## Working Directory Layout

The engine creates this structure under your chosen `WorkingDir`:

```
<WorkingDir>\
├── Logs\         DMARCReporter_YYYY-MM.log (rolling monthly)
├── Raw\          Downloaded attachments — wiped immediately after parse
├── Reports\      Parsed CSVs (dmarc_aggregate, dmarc_forensic, tlsrpt, source_inventory,
│                 dns_health, mtasts, bimi) — retained per RetentionDays
├── Temp\         Extraction work area — wiped each run
└── State\        Persistent state files (JSON):
                    progression.json         DMARC policy history per domain
                    source-inventory.json    Every sender ever seen + approval status
                    dns-health.json          Current DNS audit per domain
                    mta-sts.json             MTA-STS state per domain
                    bimi.json                BIMI deployment status per domain
                    dkim-selectors.json      DKIM signing domain history
                    cousin-domains.json      Cousin domain detections log
                    reporting-coverage.json  Which ISPs report for each domain
                    volume-baseline.json     Rolling volume baseline
                    alerts_sent.json         Alert throttle (1hr per domain)
                    last_digest.txt          Daily digest sent date
```

> Working directory ACL is auto-restricted to current user + SYSTEM + BUILTIN\Administrators on first run.

---

## Multi-Domain Support

All client domains can point `rua=mailto:dmarc@yourdomain.com` into one mailbox. The parser extracts the actual domain from each report's `<policy_published>` XML element.

For domains you don't own (clients), add the cross-domain authorization record to **their** DNS zone so report senders accept the redirect:

```
yourdomain.com._report._dmarc.<clientdomain.com>  TXT  "v=DMARC1"
```

In the dashboard, the **domain sidebar** lets you switch between portfolio view (All Domains) and per-domain deep-dives.

---

## Dashboard Tabs

| Tab | Contents |
|---|---|
| **Overview** | Compliance score gauge, pass rate, policy badge, enforcement recommendation, failure/override breakdown, reporting org coverage |
| **DMARC** | Full RUA record grid with override reasons, fail reasons, subdomain flag, cousin domain flag, sender class |
| **TLS-RPT** | TLS session failures, result types, MX hostnames |
| **Sources** | Sender inventory with approve/unapprove workflow. Filter by Unknown-Failing / New Sender / Unapproved |
| **DNS Health** | DMARC + SPF audit grid (top) + SPF chain + DKIM inspector (bottom WebBrowser) |
| **Forensic** | RUF message-level data (arrival date, source IP, header from, return path, subject, auth results) |
| **Trends** | Multi-line pass rate chart (Chart.js) + geographic sender map (Leaflet) |
| **Protocol** | MTA-STS, BIMI, DKIM signing domain status per domain |

---

## Headless / Scheduled Task

If you want to run the engine outside the dashboard (after settings are configured):

```powershell
# Engine reads settings from registry when called via Task Scheduler
# Or pass all params explicitly:

pwsh -ExecutionPolicy Bypass -File ".\src\Invoke-DMARCReporter.ps1" `
    -TenantId "YOUR-TENANT-ID" `
    -ClientId "YOUR-CLIENT-ID" `
    -MailboxAddress "dmarc@yourdomain.com" `
    -CertThumbprint "YOUR-CERT-THUMBPRINT" `
    -CertStore "LocalMachine" `
    -WorkingDir "D:\DMARC" `
    -RetentionDays 7 `
    -SourceFolder "Inbox" `
    -EnableGeoLookup `
    -EnableAlerts -AlertThresholdPct 10 -AlertEmailTo "secops@yourdomain.com" `
    -EnableNewSenderAlerts `
    -EnableVolumeAnomalyAlerts -VolumeAnomalyMultiplier 3.0 `
    -EnableDNSHealthCheck `
    -EnableCousinDomainDetection `
    -EnableReportingCoverage `
    -EnableMTASTSCheck -EnableBIMI -EnableDKIMTracking `
    -EnableDailyDigest -DigestEmailTo "admin@yourdomain.com" -DigestHour 7
```

> The dashboard's **Schedule** button creates this task for you. Manual scheduling is rarely needed.

---

## Registry Layout

All settings stored under `HKCU:\Software\DMARCMonitor\`:

- **DPAPI-encrypted** (only the user who created them can decrypt): `TenantId`, `ClientId`, `MailboxAddress`, `TeamsWebhookUrl`
- **Plain DWORD/string** (non-sensitive): `CertThumbprint`, `CertStore`, `WorkingDir`, `RetentionDays`, `SourceFolder`, all Phase 2-5 toggles

---

## Compliance Score Breakdown

Each domain scored 0-100 based on:

| Component | Max Points | Notes |
|---|---|---|
| DMARC policy level | 35 | `reject`=35, `quarantine`=20, `none`=0 |
| pct=100 | 10 | Less than 100 = partial enforcement |
| Pass rate (7d) | 20 | ≥98%=20, ≥95%=15, ≥85%=10, ≥70%=5 |
| SPF status | 10 | `-all`=10, `~all`=5, lookup count ≥10 = -5 penalty |
| MTA-STS mode | 10 | `enforce`=10, `testing`=5 |
| DKIM signing | 10 | Active signing domain detected = 10 |
| No DNS issues | 5 | Zero policy gaps = 5 |

**Score ≥80 = green, 60-79 = yellow, <60 = red** (sidebar badge color)

---

## Enforcement Recommendation Engine

The engine evaluates whether each domain is ready to advance to the next DMARC policy level:

| Current → Target | Required |
|---|---|
| `p=none` → `p=quarantine` | 14+ days of data, pass rate ≥90%, no unknown failing senders |
| `p=quarantine` → `p=reject` | 14+ days at quarantine, pass rate ≥95%, no unknown failing senders |
| `p=reject` | Verify `pct=100`, consider `adkim=s` and `aspf=s` for strict alignment |

Recommendations appear:
- In the Overview tab (top banner)
- In the daily digest email
- Via Teams alert when a domain becomes ready

---

## Event Log

All operational events logged to **Windows Event Log → Application → Source: DMARCMonitor**:

| Event ID | Meaning |
|---|---|
| 1000 | Engine start |
| 1001 | Graph auth success |
| 1002 | Graph auth failure |
| 1003 | Engine completion |
| 1004 | Unhandled exception |
| 1005 | Cert expiry warning (60-day) |
| 1006 | DMARC failure rate alert |
| 1007 | Daily digest sent |
| 1008 | DMARC policy progression |
| 1009 | MTA-STS policy changed |
| 1010 | DKIM signing domain changed |
| 1011 | New sender detected / cousin domain detected |
| 1012 | Volume anomaly detected |
| 1013 | DNS health issues found |

---

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Config or certificate error |
| 2 | Graph authentication failure |
| 3 | Mailbox connection failure |
| 4 | No new reports (informational) |
| 99 | Unhandled exception |

---

## Certificate Rotation

Certificate is valid for 2 years. The dashboard shows a red banner starting 60 days before expiry.

To rotate:
1. Open **Settings**
2. Click **Generate Certificate + Export .cer** (creates a new cert, old one stays in store)
3. Upload new `.cer` to Entra → App registrations → Certificates & secrets
4. Save Settings (thumbprint auto-updates)
5. Run Now to verify
6. Delete old cert from cert store when comfortable

---

## Frameworks & Compliance

- **NIST SP 800-53 r5:** AU-2, AU-6, AU-12, SI-4, SI-8, SC-8, SC-28
- **NIST CSF 2.0:** DE.CM (Continuous Monitoring), DE.AE (Anomalies and Events)
- **MITRE ATT&CK:** T1566.001 (Spearphishing Attachment), T1078.004 (Cloud Accounts), T1114.002 (Email Collection)
- **CISA BOD 18-01:** DKIM, SPF `-all`, DMARC `p=reject` for `.gov` domains

---

## Troubleshooting

**Banner "Microsoft.Graph.Authentication not installed"** — Click Install Now. Or manually: `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`.

**Cert thumbprint not found in CurrentUser\My / LocalMachine\My** — The thumbprint in registry doesn't match a cert in the store. Regenerate via Settings.

**"Auth failed" in run log** — Cert isn't uploaded to Entra yet, or the wrong `.cer` was uploaded. Check that the thumbprint in Entra → Certificates matches the one in Settings.

**"Mailbox connection failure"** — App access policy isn't applied, or it's pointed at the wrong group/mailbox. Re-run `Test-ApplicationAccessPolicy`.

**Scheduled task runs but no data appears in dashboard** — DPAPI is user-bound. Task must run as the user who configured the settings. Check Task Scheduler → task properties → General → "Run only when user is logged on" or use a service account that has its own profile + settings configured.

**Dashboard banner shows cert expiring** — Follow Certificate Rotation above.

**SPF Inspector tab shows "Domain Required"** — Select a specific domain in the sidebar (not "All Domains") before clicking SPF + DKIM Inspector.
