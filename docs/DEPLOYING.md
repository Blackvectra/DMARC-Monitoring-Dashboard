# Deploying it

This is the whole thing: where to run it, how to get it there, and what has to
be true before it is reachable by anybody else.

Read the last section first if you are in a hurry. It is the list of things
that, left undone, put every customer's mail data on the public internet.

---

## Where to run it

### Not Cloudflare Workers

Workers runs short-lived JavaScript and WebAssembly isolates. This is a .NET
process that holds a stateful connection open to every browser looking at it
(Blazor Server keeps a SignalR circuit per tab), keeps its database in a file
on local disk, keeps provider credentials in an encrypted file beside it, and
runs a scheduled job that reads a mailbox. None of those four things is a
thing Workers does, and the first is the one that rules it out even in
principle - there is no long-lived process for the circuit to live in.

Sign-in is not the obstacle; Cloudflare Access would handle that happily. The
obstacle is that this is a server, and Workers is not somewhere servers live.

Cloudflare is still useful in front of it, as DNS and optionally as a proxy.
That is a different job from hosting it.

### What it actually needs

One small Linux machine. Specifically:

- **2 GB of RAM.** It idles at a few hundred megabytes. The peak is an upload:
  a dropped file is read into memory before it is unpacked, so the ceiling is
  roughly the largest file anybody drops.
- **Two cores.** One is enough; two means a DNS sweep of every domain does not
  compete with somebody reading a page.
- **20 GB of disk.** The real database - 1,687 reports across ten domains -
  is 15 MB. Years of collection for thirty domains is still hundreds of
  megabytes, so the disk is for the OS.
- **A stable machine.** Not the size, the *stability*: the database is a file,
  and the provider credentials are encrypted to this machine. Somewhere that
  moves the process to a different host between requests - a serverless
  platform, a scaled-out app service - breaks both. One VM you keep is the
  right shape.

**Windows is not required.** An earlier version of this advice said it was,
because the secret store uses DPAPI; on Linux it uses AES-GCM with an
owner-only key file instead, which is in the same class of protection for this
purpose. Linux is cheaper and is what the rest of this document assumes.

### AWS or Azure

Either. Both come to roughly the same money for the same machine, and the
right answer is the one whose console you already have open - which, for you,
is AWS.

Approximate monthly cost for a 2 GB x86 Linux instance. Check current pricing;
these move:

| | roughly | notes |
|---|---|---|
| AWS Lightsail, 2 GB plan | $10–12 | flat rate, transfer and snapshots included, simplest |
| AWS EC2 `t3.small` + 20 GB gp3 | $15–17 | stoppable: pay ~$2 for the disk while it is off |
| Azure `B2ats_v2` or `B1ms` | $12–18 | stoppable, same as EC2 |
| Any of the above on Windows | add $15–30 | the licence. Not needed - see above |

**For testing**, take an EC2 or Azure VM rather than Lightsail, and stop it
when you are not using it: a week of intermittent testing is a couple of
dollars, because you pay for the disk and not the hours. Lightsail bills its
flat rate whether the instance is running or not, which is the right trade
once it is real and the wrong one while you are poking at it.

**ARM is fine** (`t4g.small` on AWS, `Dpsv5` on Azure) and is the cheapest
way to run this - about $12 a month, or a couple of dollars for a week of
testing if you stop it in between. The release publishes `linux-arm64`
alongside `linux-x64`; take whichever matches `uname -m`.

---

## Before you start

- A DNS name you control. Use a subdomain of a domain you already own -
  `dmarc.nextlayersec.io` - rather than buying one. A new domain is worth
  buying when there is something client-facing to brand, and not before.
- Permission to create an app registration in your Entra tenant, for sign-in.
- The reporting mailbox already collecting reports. See `INGEST-SETUP.md`;
  that is a separate app registration from the sign-in one, with a certificate
  rather than a secret, and it is the one that must be restricted to a single
  mailbox before its first run.

---

## 1. The machine

Ubuntu 24.04 LTS, 2 GB. Open ports 80 and 443 to the world and 22 to you.
Nothing else - in particular, **do not open the port the app listens on**. It
listens on loopback only and the proxy reaches it from the same machine.

Install the runtime and a proxy:

```bash
sudo apt update
sudo apt install -y aspnetcore-runtime-8.0 caddy unzip
```

If `aspnetcore-runtime-8.0` is not found, add Microsoft's package feed first:
<https://learn.microsoft.com/dotnet/core/install/linux-ubuntu>.

The web app is **not** self-contained - it needs that runtime on the host.
The `dmarc` command-line tool is self-contained and needs nothing.

## 2. The files

From the release page, take `dmarc-web.zip` and `dmarc-linux-x64`:

```bash
sudo useradd --system --create-home --home-dir /opt/dmarc --shell /usr/sbin/nologin dmarc

unzip -q dmarc-web.zip            # unpacks to ./dmarc-web
sudo mv dmarc-web /opt/dmarc/app
sudo mkdir -p /opt/dmarc/data
sudo chown -R dmarc:dmarc /opt/dmarc

sudo install -m 0755 dmarc-linux-x64 /usr/local/bin/dmarc
sudo -u dmarc dmarc init-db --db /opt/dmarc/data/dmarc.db
```

A dedicated account, because the provider credentials are encrypted to
whichever account writes them. Anything that touches them - the web app, and
`dmarc dns set` - must run as the same user, or the second one gets a file it
cannot read.

## 3. Configuration

`/opt/dmarc/app/appsettings.Production.json`, owned by `dmarc`, mode `0600`:

```json
{
  "Database":  { "Path": "/opt/dmarc/data/dmarc.db" },
  "Secrets":   { "Directory": "/opt/dmarc/data/secrets" },
  "Reporting": { "ProviderName": "NRG Tech Services" },

  "Proxy": { "Behind": true },

  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "TenantId": "<your tenant id>",
    "ClientId": "<the app registration from step 5>",
    "CallbackPath": "/signin-oidc"
  }
}
```

`Proxy.Behind` matters more than it looks. Without it the app sees every
request as plain HTTP from 127.0.0.1, which breaks sign-in (the redirect it
sends Entra says `http://`, the registration says `https://`, and Entra
refuses the mismatch) and would defeat the guard that keeps an
unauthenticated instance private. With it, the app trusts
`X-Forwarded-For` and `X-Forwarded-Proto` **from loopback only** - which is
right for a proxy on the same machine. A load balancer on another machine
needs `Proxy.KnownProxies` or `Proxy.KnownNetworks` set to its address or
subnet.

The proxy must also **pass the original `Host` header through**. Caddy's
`reverse_proxy` does by default, as do nginx's usual template and an AWS load
balancer. The app builds its sign-in redirect from that header, so a proxy
that rewrites it sends Entra a redirect pointing at `127.0.0.1`. Only the
scheme is taken from `X-Forwarded-Proto`; `X-Forwarded-Host` is deliberately
not trusted, because a forwarded host is a way of making an application
generate links to somewhere else.

`ProviderName` is how you are named in client reports. Left empty, reports
say "your IT provider" in so many words.

## 4. Run it

`/etc/systemd/system/dmarc-web.service`:

```ini
[Unit]
Description=DMARC Monitor
After=network.target

[Service]
User=dmarc
WorkingDirectory=/opt/dmarc/app
ExecStart=/usr/bin/dotnet /opt/dmarc/app/DmarcMonitor.Web.dll
Environment=ASPNETCORE_ENVIRONMENT=Production
Environment=ASPNETCORE_URLS=http://127.0.0.1:5000
Restart=always
RestartSec=5

# Its own directory and nothing else. /opt/dmarc rather than
# /opt/dmarc/data, because ASP.NET Core keeps the keys that sign the
# sign-in cookie under the account's home directory. Deny it that and
# the keys live only in memory, so everybody is signed out every time
# the service restarts - which reads as a flaky login, not as a
# permissions problem.
ProtectSystem=strict
ProtectHome=false
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/opt/dmarc

[Install]
WantedBy=multi-user.target
```

Loopback in `ASPNETCORE_URLS`, deliberately: the only way in is through the
proxy, so a firewall mistake cannot expose the app directly.

`/etc/caddy/Caddyfile` - this is the whole TLS setup, certificate included:

```
dmarc.nextlayersec.io {
    reverse_proxy 127.0.0.1:5000
}
```

Point the DNS A record at the instance first, then:

```bash
sudo systemctl enable --now dmarc-web
sudo systemctl reload caddy
```

Caddy gets a certificate from Let's Encrypt on first request and renews it
without being asked.

## 5. Sign-in

In the Entra admin centre, **App registrations → New registration**:

- Name: `DMARC Monitor`
- Supported account types: **this organizational directory only**
- Redirect URI: **Web**, `https://dmarc.nextlayersec.io/signin-oidc`

Then under **Authentication**, set the front-channel logout URL to
`https://dmarc.nextlayersec.io/signout-oidc`.

Copy the **Application (client) ID** and **Directory (tenant) ID** into
`appsettings.Production.json` and restart.

**No client secret is needed.** This registration only signs people in; it
calls no API on their behalf, so there is nothing to redeem a code for and
nothing that expires quietly in eighteen months. If sign-in fails with a
complaint about client authentication, that assumption was wrong for your
tenant's configuration - add a secret under `AzureAd:ClientCredentials` and
put a reminder in the calendar for its expiry.

Restrict who can sign in under **Enterprise applications → DMARC Monitor →
Properties → Assignment required**, then assign the group that should have it.
Otherwise everyone in the tenant can.

## 6. Ingest on a timer

Reports arrive continuously; something has to fetch them. `INGEST-SETUP.md`
covers the app registration and the certificate. Once that exists:

`/etc/systemd/system/dmarc-ingest.service`

```ini
[Unit]
Description=Collect DMARC reports

[Service]
Type=oneshot
User=dmarc
ExecStart=/usr/local/bin/dmarc ingest \
  --db /opt/dmarc/data/dmarc.db \
  --mailbox dmarc@nextlayersec.io \
  --tenant <tenant id> --client-id <ingest app id> \
  --cert /opt/dmarc/data/ingest.pfx
```

`/etc/systemd/system/dmarc-ingest.timer`

```ini
[Unit]
Description=Collect DMARC reports hourly

[Timer]
OnCalendar=hourly
RandomizedDelaySec=600
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now dmarc-ingest.timer
```

`Persistent=true` catches up after the machine has been off. The randomised
delay keeps you off the exact hour, which is when everybody else's jobs run.

Run it once by hand with `--dry-run` first. It parses and reports and writes
nothing, which is safe against a live mailbox.

## 7. MTA-STS, if you want it

The app serves the policy file, so one instance can serve every client's:

```bash
sudo -u dmarc dmarc mta-sts set --domain example.com --db /opt/dmarc/data/dmarc.db
```

Then add a CNAME per domain - `mta-sts.example.com` pointing at this host -
and a Caddy block so the certificate covers it:

```
mta-sts.example.com, mta-sts.another-client.com {
    reverse_proxy 127.0.0.1:5000
}
```

Caddy gets a certificate for each name on first request. The app answers
`/.well-known/mta-sts.txt` by the Host it arrived on, so it serves the right
client's policy without any per-domain configuration beyond the row.

Then `dmarc fix --domain example.com --apply --reason "..."` publishes the TXT
record that announces it. In that order: the record announces a policy, and
announcing one nothing is serving does nothing at all.

## 8. Backups

Two files matter and they are both small:

```bash
sudo -u dmarc sqlite3 /opt/dmarc/data/dmarc.db ".backup '/opt/dmarc/data/backup.db'"
```

`.backup` rather than `cp`, because copying a SQLite file while something has
it open can produce a file that looks fine and is not. Then take
`backup.db` and the `secrets/` directory off the machine.

The secrets directory is encrypted to **this machine and this account**. A
restore onto a new machine cannot read it: the database rows keep working,
but every DNS provider credential has to be entered again. That is the
intended behaviour - it is why a stolen backup is not a stolen Cloudflare
token - and it is worth knowing before the day you need the restore.

## 9. Releases, and keeping this machine stable

The point of this section: **work in progress must not arrive on a machine
managing customers' DNS just because somebody merged something.**

So there are two separate things, and only one of them reaches this server:

| | where it lives | what reaches the server |
|---|---|---|
| Development | branches, then `main` | nothing |
| A release | a `v*` tag | the artifacts that tag built |

Tagging is the decision. Until you tag, you can change whatever you like on
`main` and this box keeps running what it has.

```bash
git tag v1.3.0 && git push origin v1.3.0
```

That builds `dmarc.exe`, `dmarc-linux-x64`, `dmarc-linux-arm64` and
`dmarc-web.zip`, stamps each with `1.3.0`, and attaches them to a GitHub
release.

**The server can tell you when it is behind.** Set `Updates:Repository` in
`appsettings.Production.json` and the Settings page reports what it is running
and whether a newer release exists:

```json
"Updates": {
  "Repository": "Blackvectra/DMARC-Monitoring-Dashboard",
  "Channel": "stable",
  "Token": ""
}
```

`stable` ignores anything marked prerelease, so tagging `v1.4.0-rc1` and
marking it a prerelease on GitHub lets you test it on one box (`"Channel":
"preview"`) without every other instance being told to install it. `Token` is
needed only if the repository is private, and a read-only one is enough.

**The Updates page has a button**, and the interesting part is how it works.
The web app runs as the unprivileged `dmarc` account and cannot replace its
own files - it holds the credentials that rewrite your customers' DNS, and a
web application that can also install software is a far larger thing to have
compromised. So pressing Install writes down a version number, and a separate
systemd unit running as root notices and does the work:

```bash
sudo ./deploy/install-update-agent.sh
```

The only thing crossing that boundary is a version string. The agent treats it
as hostile anyway: it must match a narrow version shape, and it must be a
release that really exists on the configured channel, which the agent checks
against GitHub itself rather than trusting the request. So the worst an
attacker who owned the web app could achieve through this is installing a
genuine release of this product.

Without the agent installed the page still lists releases and says plainly
that it cannot install them. The command works either way:

```bash
sudo ./deploy/update.sh v1.3.0
```

Both paths run the same script, which backs up the database with SQLite's own `.backup`, keeps the old install
rather than overwriting it, carries `appsettings.Production.json` across,
applies any schema migration *after* the new binary is in place and *before*
the service starts, and checks the app answers afterwards - putting the old
one back if it does not.

Rolling back is a move, not a download:

```bash
sudo ./deploy/rollback.sh 20260918-120000              # the application
sudo ./deploy/rollback.sh 20260918-120000 --database   # and the database
```

Those are two decisions on purpose. Swapping the application back is always
safe. Restoring the database is not always wanted: if the version you are
leaving applied no migration, the current database is fine and holds
everything collected since the update, which restoring would discard.

## Before it is reachable by anybody else

- [ ] `AzureAd` is filled in and signing in works. **Until it is, the app has
      no login at all.** It refuses to serve anything but loopback in that
      state, and refuses proxied requests outright, so a half-finished
      deployment fails closed - but do not leave it half-finished.
- [ ] `Auth:AllowLocalModeRemotely` is **not** set. It exists to be turned on
      deliberately and defeats the protection above.
- [ ] Every page shows your name in the top corner, not `root`.
- [ ] The app is listening on `127.0.0.1` only: `ss -ltn | grep 5000`.
- [ ] Only 80, 443 and your SSH source are open in the security group.
- [ ] `appsettings.Production.json` is `0600` and owned by `dmarc`.
- [ ] The ingest app registration is restricted to one mailbox by an
      application access policy (`INGEST-SETUP.md`, step 4). Without it, the
      certificate reads every mailbox in the tenant.
- [ ] A backup has been taken *and restored somewhere* at least once.
- [ ] If the repository is private and the Updates page is in use, the token
      is in `/etc/dmarc-update.env` at mode `0600` owned by root - **not** in
      the app's configuration, which the unprivileged account can read.

## On Windows instead

The same shape, with different names: IIS with the ASP.NET Core Hosting
Bundle in place of Caddy, an application pool identity in place of the `dmarc`
user, Task Scheduler in place of the systemd timer, win-acme for the
certificate. `Proxy:Behind` still has to be `true` - IIS is a reverse proxy
like any other.

The one genuine difference is the secret store: on Windows it is DPAPI, keyed
to the account that writes the secret. The application pool identity and
whoever runs `dmarc dns set` must be the same account, or the app will find a
credential it cannot decrypt and say so.

## What has not been tested

Honesty about the gaps, so you meet them knowing rather than at 11pm:

- **None of this has been run end to end on a real VM.** It is assembled from
  how the pieces are built rather than from a deployment that happened. The
  proxy handling is covered by tests; the systemd units and the Caddyfile are
  not.
- **Sign-in through Entra has never been performed.** The code path is
  exercised by tests only in its not-configured state. Expect to spend an hour
  on the app registration.
- **The secret store has not been exercised on Windows**, only on Linux, where
  the AES-GCM path is the one that runs.
- **No ARM build**, so the cheapest instance sizes are unavailable.

See `OPEN-ISSUES.md` for the rest.
