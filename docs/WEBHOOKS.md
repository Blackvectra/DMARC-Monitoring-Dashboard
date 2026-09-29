# Webhooks

What the nightly DNS scan finds, sent somewhere as it is found: a signed JSON
`POST` per change, to one address per organization. A PSA, a SOC console, a
small relay in front of a chat tool — anything that can check an HMAC.

Without one, a weakened DMARC policy is learned about by opening the app.

The same changes can be filed as tickets in ConnectWise PSA instead of, or
as well as, being POSTed here: [`CONNECTWISE.md`](CONNECTWISE.md). It is the
same channel with a second kind of destination, so everything below about
when things are sent, what is not, and what `dmarc health` watches applies to
both.

---

## What is sent, and when

`dmarc-dns.service` reads every domain's records nightly at 03:20. When it
exits cleanly, `OnSuccess=` starts `dmarc-notify.service`, which runs
`dmarc notify send` and exits. There is no timer of its own and nothing
listening.

Each DNS change the scan recorded is sent once, oldest first, if it is at or
above the webhook's minimum severity:

| severity | for example |
|---|---|
| `critical` | DMARC `p=` or `sp=` loosened; a DMARC report address taken away; DMARC or SPF removed or no longer parsing; a second SPF record published |
| `warning` | DMARC `p=` or `sp=` tightened, `pct=` lowered or alignment changed; an SPF mechanism removed or its `all` weakened; MTA-STS or TLS-RPT withdrawn |
| `info` | a record published; an SPF include added; any other change |

The default is `warning`. The rules are `DnsDrift.cs`; this table is a
summary of them, not a second copy.

Some things are deliberately not sent:

- **Changes from before the webhook existed.** Setting one up is not a request
  for every change the product has ever seen.
- **Anything more than 14 days old** that has still not been delivered. After
  two weeks it is history, and the drift page still has it.

A change to a domain this product itself changed in the two days before
(applied from the Fix page and not rolled back) is still sent, with
`wasExpected: true`, so the receiver can decide.

### When the receiver is down

A run stops at the first failure, so events arrive in order or not at all. The
next night's run tries the stuck one first. A receiver that is down for a
night loses nothing.

`dmarc health` watches it:

| | reported as |
|---|---|
| the last attempt failed, but something was delivered in the last 36 hours | a weakness |
| nothing delivered for 36 hours, and the last attempt failed | **breaking** — which is the exit code, so `dmarc-health`'s `OnFailure=` alert fires |

`dmarc-notify.service` has its own `OnFailure=dmarc-alert@%N.service` too, so
a failed delivery is announced the morning it happens.

---

## Setting one up on a server

Generate a signing key. Give the same value to the receiver.

```sh
openssl rand -hex 32
```

Then, as the service account, so that it lands in the secret store the
service reads:

```sh
sudo -H -u dmarc /usr/local/bin/dmarc notify set --org <slug> \
    --url https://console.example/api/sources/dmarc-monitor/events \
    --min-severity warning \
    --link-base https://dmarc.example.com \
    --db /opt/dmarc/data/dmarc.db --secrets /opt/dmarc/data/secrets
```

It asks for the key at a prompt that does not echo. The key never goes on the
command line — shell history, `ps`, the screenshot on the ticket. For a script,
`--secret-stdin` reads it from standard input, or `DMARC_WEBHOOK_SECRET` from
the environment.

`--link-base` is the address people open the web app on; each event carries a
link to the domain's page there. Leave it out and events carry no link.

`--org` is the organization's slug (`local` if there is only one). Each
organization has at most one webhook; setting it again replaces the address
and key and keeps the record of what was already sent.

Prove it before there is anything to send:

```sh
sudo -H -u dmarc /usr/local/bin/dmarc notify test --org <slug> \
    --db /opt/dmarc/data/dmarc.db --secrets /opt/dmarc/data/secrets
```

That sends a `ping` event, signed like any other, and prints what came back.

The rest:

```sh
# what is configured, where it goes, and whether it is failing
sudo -H -u dmarc /usr/local/bin/dmarc notify list --db /opt/dmarc/data/dmarc.db --secrets /opt/dmarc/data/secrets

# send what is waiting now, rather than after tomorrow's scan
sudo systemctl start dmarc-notify

# stop sending, and forget the address and key
sudo -H -u dmarc /usr/local/bin/dmarc notify remove --org <slug> \
    --db /opt/dmarc/data/dmarc.db --secrets /opt/dmarc/data/secrets
```

Setting, replacing and removing are written to the audit log with who did it
and the destination's scheme and host. Not the full address.

### What is stored where

The database holds the destination's scheme and host (`https://console.example`)
for display, the minimum severity, and which events went where. The full
address and the signing key are in the secret store, because for most chat
tools the address is itself the credential. A copied database or a backup
carries neither.

A run given a different `--secrets` from the one that set the webhook finds no
key and says so, rather than sending unsigned.

### Plain HTTP

Refused, except to `127.0.0.1`, `localhost` and `[::1]` — a receiver on the
same machine, or one being tried out.

### One Windows desktop

The Windows download, run as yourself, with the receiver on the same machine
(the MSP Security Operations Console under Docker Desktop, for one).

The key is kept with DPAPI for **the Windows account that set it**, so set it
and send as the same account. That is you, so the nightly job below runs as
you too.

In PowerShell 7, from the folder holding `dmarc.exe` and `dmarc.db`:

```powershell
# The same key the receiver has. For the console, it is in its .env file.
$key = ((Get-Content 'C:\path\to\msp-security-ops-console\.env') -match '^DMARC_MONITOR_SECRET=') -replace '^DMARC_MONITOR_SECRET=', ''
$key | .\dmarc.exe notify set --org local --url http://localhost:8080/api/sources/dmarc-monitor/events --secret-stdin
.\dmarc.exe notify test --org local
```

Plain HTTP is accepted because `localhost` never leaves the machine.

Then the nightly scan and send, as a task that runs as you:

```powershell
$dir       = (Get-Location).Path
$action    = New-ScheduledTaskAction -Execute 'cmd.exe' -WorkingDirectory $dir `
               -Argument '/c (dmarc.exe check --all --save & dmarc.exe notify send) >> nightly.log 2>&1'
$trigger   = New-ScheduledTaskTrigger -Daily -At 3:20am
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable
Register-ScheduledTask -TaskName 'DMARC scan and notify' -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings
```

- `Interactive` means it runs while you are signed in. A locked screen counts.
  `-StartWhenAvailable` runs a missed night at the next sign-in.
- The send runs even when the scan reports broken records, which is the scan
  working.
- A delivery that fails is kept and retried the next night. It shows in
  `nightly.log` and in `.\dmarc.exe notify list`.

Not for the Windows *service* install (`bootstrap.ps1`). Its tasks run as
`NT AUTHORITY\LocalService`, which cannot read a key you set from your own
session, and it has no task that sends after the scan yet.

---

## The contract

### The request

```
POST <url>
Content-Type: application/json; charset=utf-8
User-Agent: DmarcMonitor/<version>
X-Dmarc-Event-Id: 4f0c2a52-9d63-4b8e-a0c1-2b7e6f1d9a10
X-Dmarc-Timestamp: 1790000000
X-Dmarc-Signature: v1=ea9dc5229cf57493b6afd4de88a5b1b0f99901b6427f97ed78cf64e5da36f721
```

Any `2xx` is delivered. Anything else, a timeout (20 seconds) or a redirect is
a failure and is tried again next run. Redirects are not followed: a signed
request going somewhere it was not sent is not something to do quietly.

### The body

```json
{
  "schema": "dmarc-monitor.event.v1",
  "id": "4f0c2a52-9d63-4b8e-a0c1-2b7e6f1d9a10",
  "type": "dns.drift",
  "occurredAt": "2026-09-27T03:20:41+00:00",
  "organization": { "id": "<organization id>", "slug": "local" },
  "client": { "id": "<client id>", "slug": "client-a", "name": "Client A" },
  "domain": "example.com",
  "severity": "critical",
  "summary": "DMARC: p=quarantine → p=none.",
  "wasExpected": false,
  "dnsDrift": {
    "recordType": "dmarc",
    "oldValue": "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
    "newValue": "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
  },
  "link": "https://dmarc.example.com/domains/example.com"
}
```

| field | |
|---|---|
| `schema` | `dmarc-monitor.event.v1`. A breaking change gets a new one |
| `id` | the drift event's id. **The same on every retry** — deduplicate on it |
| `type` | `dns.drift`, or `ping` from `dmarc notify test`. Ignore types you do not know |
| `occurredAt` | when the scan saw the change, not when it was sent |
| `recordType` | `spf`, `dmarc`, `mta-sts` or `tls-rpt` |
| `oldValue`, `newValue` | the record text; either is absent when the record was published or removed |
| `link` | absent unless `--link-base` was given |

A `ping` carries `schema`, `id`, `type`, `occurredAt`, `organization` and a
`summary` saying it is a test, and nothing else.

### Verifying it

```
signature = "v1=" + hex( HMAC-SHA256( key, timestamp + "." + body ) )
```

- `key` is the UTF-8 bytes of the key as typed, not hex-decoded.
- `body` is the raw request body, byte for byte, before any JSON parsing.
- Compare in constant time.
- Refuse a timestamp more than five minutes from your own clock. The
  timestamp is signed, so a captured request cannot be replayed with a fresh
  one.

A check against this, for any receiver:

| | |
|---|---|
| key | `contract-test-secret-0123456789abcdef` |
| timestamp | `1790000000` |
| body | `{"schema":"dmarc-monitor.event.v1","id":"4f0c2a52-9d63-4b8e-a0c1-2b7e6f1d9a10","type":"ping"}` |
| signature | `v1=ea9dc5229cf57493b6afd4de88a5b1b0f99901b6427f97ed78cf64e5da36f721` |

The sender's tests assert exactly this, so it cannot move without failing
them.

```python
import hmac, hashlib
def verify(key: str, timestamp: str, body: bytes, header: str) -> bool:
    mac = hmac.new(key.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return hmac.compare_digest("v1=" + mac.hexdigest(), header or "")
```

### What a receiver should do

- Answer `2xx` once the event is stored, not once it is acted on.
- Answer `2xx` to an `id` it has already stored. It will see the same one again
  whenever its previous answer did not arrive.
- Answer `2xx` to an event it chooses to ignore, or it will be sent again every
  night for two weeks.
- Answer `4xx` only for what retrying will not fix, and expect it to be retried
  anyway: the sender does not tell the difference, and the failure is what
  makes `dmarc health` notice.
