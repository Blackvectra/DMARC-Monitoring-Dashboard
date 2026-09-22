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

**On AWS specifically**, [`AWS.md`](AWS.md) is the console-by-console version
of this page: the IAM role that lets you skip SSH entirely, the security
group, the instance, the Elastic IP, and then the part this page does not
cover at all — requiring MFA and passkeys so the thing is safe to leave open
on 443 for a phone.

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
| Any of the above on Windows | add $15–30 | the license. Not needed - see above |

**For testing**, take an EC2 or Azure VM rather than Lightsail, and stop it
when you are not using it: a week of intermittent testing is a couple of
dollars, because you pay for the disk and not the hours. Lightsail bills its
flat rate whether the instance is running or not, which is the right trade
once it is real and the wrong one while you are poking at it.

**ARM is fine** (`t4g.small` on AWS, `Dpsv5` on Azure) and is the cheapest
way to run this - about $12 a month, or a couple of dollars for a week of
testing if you stop it in between. The release publishes `linux-arm64`
alongside `linux-x64`; take whichever matches `uname -m`, which is what
`bootstrap.sh` does for you.

Both architectures are built on the machine they target and installed end to
end by CI on every change - the whole `install.sh` run, the web app answering,
the timers enabled, a backup taken and a health check passed. That was not
true until recently: `linux-arm64` was cross-compiled from an x64 runner and
published having never been executed, which is worth knowing if you are
reading an older release's notes.

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

## The short version: one command

Steps 1 to 4 below, and as much of 5 and 6 as you hand it, are one script.
On a fresh Linux machine whose DNS name already points at it:

```bash
curl -fsSL https://raw.githubusercontent.com/Blackvectra/DMARC-Monitoring-Dashboard/main/deploy/bootstrap.sh \
  | sudo bash -s -- --host dmarc.nextlayersec.io --email you@nrgtechservices.com
```

On Windows, from an elevated PowerShell, with `deploy/bootstrap.ps1` from the
release's `dmarc-deploy.tar.gz`:

```powershell
.\bootstrap.ps1 -HostName dmarc.nextlayersec.io -Email you@nrgtechservices.com
```

Either one installs the runtime and Caddy, downloads the latest release,
installs the service listening on loopback, puts Caddy in front of it with a
certificate, and installs the update agent. It ends with the exact Entra
steps still to do. Re-running it is safe: on an installed machine it only
applies configuration, which is how sign-in and the mailbox are added later:

```bash
sudo ./deploy/bootstrap.sh --host dmarc.nextlayersec.io \
    --tenant-id <directory id> --client-id <application id>          # sign-in (step 5)

sudo ./deploy/bootstrap.sh --host dmarc.nextlayersec.io --make-ingest-cert \
    --mailbox dmarc@nrgtechservices.com \
    --ingest-tenant-id <directory id> --ingest-client-id <ingest app id>   # the collector (step 6)
```

After a run that was piped through `bash`, the copy to re-run is
`/opt/dmarc/deploy/bootstrap.sh`; the script ends by printing the exact
command. The same arguments exist on Windows with PowerShell spelling
(`-TenantId`, `-MakeIngestCert`, ...). `--help` lists everything. The steps
below are what it does, so that it is not magic - and so that a machine it
does not know can still be set up by hand.

---

## 1. The machine

Ubuntu 24.04 LTS or Amazon Linux 2023, 2 GB. Open ports 80 and 443 to the
world and 22 to you. Nothing else - in particular, **do not open the port the
app listens on**. It listens on loopback only and the proxy reaches it from
the same machine. On AWS the security group is the firewall; neither image
runs one of its own.

The web app is **not** self-contained - it needs the ASP.NET Core 8 runtime
on the host. The `dmarc` command-line tool is self-contained and needs
nothing. Caddy is the proxy, because it is the whole TLS setup in three lines
and renews the certificate itself.

**Ubuntu 24.04** - everything is in Ubuntu's own repositories:

```bash
sudo apt update
sudo apt install -y aspnetcore-runtime-8.0 caddy unzip sqlite3
```

If `aspnetcore-runtime-8.0` is not found, add Microsoft's package feed first:
<https://learn.microsoft.com/dotnet/core/install/linux-ubuntu>.

**Amazon Linux 2023** - the runtime and the tools are in Amazon's own
repositories. Caddy is not, so it is the static binary from Caddy's download
service, installed the way Caddy's documentation describes:

```bash
sudo dnf install -y aspnetcore-runtime-8.0 unzip sqlite

# Caddy. arch=amd64 on x86_64; arch=arm64 on a t4g.
curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=amd64" -o caddy
sudo install -m 0755 caddy /usr/bin/caddy
sudo groupadd --system caddy
sudo useradd --system --gid caddy --create-home --home-dir /var/lib/caddy \
    --shell /usr/sbin/nologin --comment "Caddy web server" caddy
sudo mkdir -p /etc/caddy
sudo curl -fsSL https://raw.githubusercontent.com/caddyserver/dist/master/init/caddy.service \
    -o /etc/systemd/system/caddy.service
sudo systemctl daemon-reload
```

Two things about Amazon Linux that differ from Ubuntu and do not matter
here, said so they are not wondered about. It ships with SELinux in
permissive mode: nothing is blocked, denials are only logged, and nothing
below needs a context set. And the package that provides `sqlite3` is called
`sqlite` - `install.sh` and `update.sh` name the right package for whichever
machine they are on when something is missing.

## 2. Install

From the release page, three files: `dmarc-web.zip`, `dmarc-linux-x64` (or
`dmarc-linux-arm64` - take whichever matches `uname -m`), and
`dmarc-deploy.tar.gz`, which holds the install, update and rollback scripts
and the systemd units. The server has no checkout; that is why they travel
with the release.

Not `DMARC-Monitor-Windows.zip`. That one is a self-contained copy for looking
at the product on a laptop - no runtime, no service, no sign-in, serving
loopback only. It is the right way to decide whether to do any of this, and
the wrong thing to put on a server: it has no authentication because it has
no way to be reached by anybody but the person running it.

```bash
tar xzf dmarc-deploy.tar.gz
sudo ./deploy/install.sh
```

It refuses to run over an existing install (that is `update.sh`'s job), never
overwrites a configuration file, and finishes by checking the app answers on
loopback. What it did, so that it is not magic:

- Created a `dmarc` system account with `/opt/dmarc` as its home. A dedicated
  account, because the provider credentials are encrypted to whichever
  account writes them. Anything that touches them - the web app, and
  `dmarc dns set` - must run as the same user, or the second one gets a file
  it cannot read.
- Unpacked the web app to `/opt/dmarc/app`, installed the command as
  `/usr/local/bin/dmarc`, and created the database at
  `/opt/dmarc/data/dmarc.db` as that account.
- Wrote `/opt/dmarc/app/appsettings.Production.json` (step 3) and
  `/etc/dmarc-ingest.env` (step 6) as templates.
- Installed every unit in `deploy/` - `dmarc-web.service`, the collector pair
  `dmarc-ingest.service`/`.timer` and its templated equivalents
  `dmarc-ingest@.service`/`.timer`, `dmarc-dns`, `dmarc-prune`,
  `dmarc-backup`, `dmarc-health` and `dmarc-alert@.service` - and started the
  web app.
- **Enabled four timers**, all of which need nothing configured to be useful:

  | timer | what, and when |
  |---|---|
  | `dmarc-dns.timer` | nightly 03:20 - reads every domain's published SPF, DKIM and DMARC records. Fills the Records column on the domains page |
  | `dmarc-backup.timer` | nightly 03:20 - a verified copy into `/opt/dmarc/backups`, 14 kept |
  | `dmarc-health.timer` | 09:10 and 21:10 - whether collection and backups are still happening |
  | `dmarc-prune.timer` | Sunday 04:40 - the retention window, aggregate 400 days and forensic 30 |

  Each can be run by hand at any time with `sudo systemctl start dmarc-dns`
  and so on.
- **Took the first backup**, rather than leaving it until 03:20 tomorrow. It
  is the run that proves the thing works on this machine, and without it the
  health check above fails on the evening of install day over a copy that has
  not had a chance to exist.

The collector is the one thing NOT enabled: it cannot run until you have
finished an app registration and given it a certificate, and an hourly unit
failing on an empty environment file is worse than one you had to switch on.

Somewhere other than `/opt/dmarc`, or under a different account name:
`DMARC_ROOT=/srv/dmarc DMARC_USER=svc-dmarc sudo -E ./deploy/install.sh`.
Every script under `deploy/` honours the same two variables, and the units are
rewritten to match and then checked for anything still pointing at the
default.

Until sign-in is configured the app serves nothing but this machine. To see it
before then, tunnel: `ssh -L 5000:127.0.0.1:5000 <server>` and open
<http://127.0.0.1:5000>.

## 3. Configuration

`/opt/dmarc/app/appsettings.Production.json`, owned by `dmarc`, mode `0600`.
`install.sh` wrote it with the paths filled in and the rest empty; this is
what a finished one looks like:

```json
{
  "Database":  { "Path": "/opt/dmarc/data/dmarc.db" },
  "Secrets":   { "Directory": "/opt/dmarc/data/secrets" },
  "Reporting": {
    "ProviderName": "NRG Tech Services",
    "TlsReportAddress": "dmarc@nrgtechservices.com"
  },

  "MtaSts": { "PolicyHost": "dmarc.nextlayersec.ai" },

  "Proxy": { "Behind": true },

  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "TenantId": "<your tenant id>",
    "ClientId": "<the app registration from step 5>",
    "CallbackPath": "/signin-oidc"
  }
}
```

`Reporting.TlsReportAddress` is where TLS-RPT reports are asked to be sent,
and the Fix page reads it to decide whether to offer publishing a `_smtp._tls`
record at all. Leave it out and TLS-RPT is simply never planned for any
domain, with nothing on the page to say why - the alternative would be
planning a record that points at a mailbox nobody reads. The command line
takes it per run instead, as `dmarc fix --domain <d> --tls-rpt-to <address>`,
so this key is what makes the button appear in the UI.

`MtaSts.PolicyHost` is the hostname this instance answers on. MTA-STS has two
halves: a TXT record at `_mta-sts.<domain>` announcing that a policy exists,
and the policy file itself, which a sender fetches from
`https://mta-sts.<domain>/.well-known/mta-sts.txt`. This app serves that file
for every client from the Host header, so each client's `mta-sts.<domain>` is a
CNAME pointing here — and that means **this host needs a certificate valid for
every one of those names**, because a sender will not follow a redirect or
accept a certificate that does not match. Set this and the Fix page can tell
you exactly what to publish; leave it empty and it can only say that something
needs pointing somewhere.

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

## 4. The proxy

The web app is already running as `dmarc-web.service`, listening on
`127.0.0.1:5000`. Loopback, deliberately: the only way in is through the
proxy, so a firewall mistake cannot expose the app directly. The unit is
`deploy/dmarc-web.service`, and the part worth knowing is the sandbox at the
bottom of it: the process can write to `/opt/dmarc/data` and nowhere else,
the rest of the filesystem is read-only to it, and its home directory is
hidden. The cookie-signing keys live under `data/keys` for exactly that
reason - left to itself ASP.NET Core keeps them under the home directory,
would find it hidden, keep them in memory only, and sign everybody out on
every restart.

`/etc/caddy/Caddyfile` - this is the whole TLS setup, certificate included:

```
dmarc.nextlayersec.io {
    reverse_proxy 127.0.0.1:5000
}
```

Point the DNS A record at the instance first, then:

```bash
sudo systemctl enable --now caddy     # already so on Ubuntu; needed on Amazon Linux
sudo systemctl reload caddy
```

Caddy gets a certificate from Let's Encrypt on first request and renews it
without being asked.

## 5. Sign-in

In the Entra admin center, **App registrations → New registration**:

- Name: `DMARC Monitor`
- Supported account types: **this organizational directory only**
- Redirect URI: **Web**, `https://dmarc.nextlayersec.io/signin-oidc`

Then under **Authentication**:

- Add a second redirect URI, `https://dmarc.nextlayersec.io/signout-callback-oidc`.
  Sign-out sends people back there, and Entra only sends people to registered
  addresses; without it, signing out ends on a Microsoft page telling you to
  close the browser.
- Front-channel logout URL: `https://dmarc.nextlayersec.io/signout-oidc`.
- Under *Implicit grant and hybrid flows*, tick **ID tokens (used for
  implicit and hybrid flows)**. This app signs people in without a client
  secret, which is the ID-token flow, and Entra refuses that flow until the
  box is ticked (the error names `response_type`). Two Microsoft pages say
  not to tick it; they describe apps that also call an API with a secret,
  which this one does not.
- Save.

Copy the **Application (client) ID** and **Directory (tenant) ID** into
`appsettings.Production.json` (or hand them to `bootstrap.sh --tenant-id
--client-id`) and restart.

**No client secret is needed.** This registration only signs people in; it
calls no API on their behalf, so there is nothing to redeem a code for and
nothing that expires quietly in eighteen months. If sign-in fails with a
complaint about client authentication, that assumption was wrong for your
tenant's configuration - add a secret under `AzureAd:ClientCredentials` and
put a reminder in the calendar for its expiry.

Restrict who can sign in under **Enterprise applications → DMARC Monitor**:
first **Permissions → Grant admin consent** (once assignment is required,
users can no longer consent for themselves, and the first sign-in otherwise
ends in "Need admin approval"), then **Properties → Assignment required =
Yes**, then **Users and groups** → add the people or the group that should
have it. Otherwise everyone in the tenant can. Assigning a group needs an
Entra ID P1 license; on a free tenant assign people individually.

### Organizations: who sees which clients

Clients belong to an organization, and an organization's people see its
clients and domains and nothing else. NRG Tech Services and NextLayerSec are
two organizations in one install; an NRG employee never sees a NextLayerSec
client, and a domain of the other organization answers "nothing stored"
exactly as a domain that does not exist would.

Who belongs where is decided by Entra security groups, which the token has
to carry:

- Under the app registration, **Token configuration → Add groups claim →
  Security groups**, with the group ID as the claim value. Without this the
  token names no groups, everybody signed in belongs to nothing, and the
  page says so.
- Create one security group per organization, and one master group for the
  people who run the whole thing. Copy each group's **Object ID**.
- Tell the app the master group: `Auth:MasterGroupId` in
  `appsettings.Production.json` (or `bootstrap.sh --master-group-id <id>`).
  Members see every organization and get a switcher in the sidebar; with
  "All organizations" chosen, every page shows which organization each row
  belongs to.
- Tell each organization its group, on the Settings page as a master, or
  with `dmarc org set-group --org <slug> --group <id>`. The built-in
  organization is filed as `local`; rename it there too, or with
  `dmarc org rename --org local --name "NRG Tech Services"`.

#### Roles within an organization

Each organization has up to three groups, one per role. The strongest group
somebody is in wins, so adding a person to a stronger group never means
removing them from the weaker one first.

| Role | Group | May |
| --- | --- | --- |
| Viewer | `--role viewer` | Read every page in scope. Nothing else. |
| Operator | `--role operator` (the default) | Also assign and move domains, add clients, import reports, apply and roll back DNS changes. |
| Admin | `--role admin` | Also set this organization's groups, branding and DNS providers, and read its activity log. |
| Master | `Auth:MasterGroupId` | Every organization, and creating new ones. |

```bash
dmarc org set-group --org nrg-tech-services --role admin    --group <id>
dmarc org set-group --org nrg-tech-services --role operator --group <id>
dmarc org set-group --org nrg-tech-services --role viewer   --group <id>
```

An admin can do the same from **Settings → Organizations → Edit** for their
own organization. The sidebar says which role the person has, so a viewer
who cannot find the Apply button knows it is not missing.

#### A customer's own login

A client can have a group of its own. Its members see that one client, read
only, with no Clients, Import, Settings or Updates in the sidebar, and every
other client of the organization answers "nothing stored" the way a domain
that does not exist would. Guests invited into your directory work, so a
customer signs in with their own email address.

```bash
dmarc client set-group --client morton-nd --group <id>
```

Or **Clients → Customer login group** as an admin. Somebody who is also in a
staff group keeps the staff role: being a customer never takes access away.

#### White-label

Per organization: an accent color, a logo in the sidebar, the name the
reports are prepared by, and a contact block for their footer. Set it under
**Settings → Organizations → Edit**, or:

```bash
dmarc org brand --org nextlayersec --color '#0f766e' \
    --provider-name "NextLayerSec" --contact 'dmarc@nextlayersec.io\n+1 555 0100' \
    --logo ./nextlayersec.png
```

The color has to be a six-digit hex and the logo a PNG, JPEG, GIF, WebP or
SVG of at most 200 KB: both end up in markup, so anything else is refused.
`--clear` puts an organization back to the default look.

#### Who changed what

Changes made through the web app - organizations, groups, branding, clients,
customer logins, DNS providers and imports - are recorded with who made them.
Admins and masters read it under **Settings → Recent activity**. DNS changes
keep their own, fuller trail on the Fix page.

A second organization is `dmarc org add --name "NextLayerSec" --group <id>`
(or Settings → Organizations as a master). Its clients are created with
`--org nextlayersec`, or from the Clients page while looking at it. A
collector for its own mailbox files new domains there with `--org
nextlayersec` (`DMARC_ORGANIZATION` in the environment file); a domain
already known keeps its organization whichever mailbox sees it. Assigning a
domain to a client in another organization moves it there, history and all,
and only somebody who can see both can do that.

Without sign-in configured there are no groups to read, and whoever is at
the machine is treated as the master.

## 6. Ingest on a timer

Reports arrive continuously; something has to fetch them. `INGEST-SETUP.md`
covers the app registration. The shortest route from there is one command,
which makes the certificate, prints the `.cer` to upload, fills in the
environment file below and enables the timer:

```bash
sudo ./deploy/bootstrap.sh --host dmarc.nextlayersec.io --make-ingest-cert \
    --mailbox dmarc@nextlayersec.io --ingest-tenant-id <tenant id> --ingest-client-id <ingest app id>
```

By hand instead: put the certificate at `/opt/dmarc/data/ingest.pfx`, owned
by `dmarc`, mode `0600`, and fill in `/etc/dmarc-ingest.env` - root-owned,
mode `0600`, written by `install.sh`:

```
DMARC_MAILBOX=dmarc@nextlayersec.io
DMARC_TENANT_ID=<tenant id>
DMARC_CLIENT_ID=<ingest app id>
DMARC_CERT_PATH=/opt/dmarc/data/ingest.pfx
DMARC_CERT_PASSWORD=
DMARC_FALLBACK_ADDRESS=
DMARC_REPORTING_DOMAIN=
```

The last two say how a report is attributed to a domain and are usually left
empty: every domain's `rua` points at the one shared mailbox, so the mailbox
itself is the address. Set `DMARC_FALLBACK_ADDRESS` if the `rua` address is an
alias or group rather than the mailbox's own address, and
`DMARC_REPORTING_DOMAIN` only if per-domain addresses like
`client.com@rua.example.com` are in use. Getting it wrong loses nothing: reports
to an address the collector does not recognize are left in the mailbox and the
run says which address to set.

`dmarc-ingest.service` reads the file and runs `dmarc ingest` as the `dmarc`
account with those in its environment, which keeps the certificate password
off a command line where `ps` would show it. Run it once by hand with
`--dry-run` first - it parses and reports and writes nothing, which is safe
against a live mailbox:

```bash
sudo bash -c 'set -a; . /etc/dmarc-ingest.env; exec sudo -E -H -u dmarc \
    dmarc ingest --db /opt/dmarc/data/dmarc.db --mailbox "$DMARC_MAILBOX" --dry-run'
```

The `-H` is load-bearing. `-E` carries the environment file's values across to
the `dmarc` account, and without `-H` it carries root's `HOME` with them - so
the binary tries to unpack itself under `/root`, cannot, and dies with the
exit 159 described below before it has read a single message.

Then:

```bash
sudo systemctl enable --now dmarc-ingest.timer
```

Hourly, give or take ten minutes. `Persistent=true` catches up after the
machine has been off, and the randomised delay keeps you off the exact hour,
which is when everybody else's jobs run.

One thing about the `dmarc` binary worth knowing before it bites: it is a
single self-contained file that unpacks its native SQLite library the first
time it runs, into `$HOME/.net` unless `DOTNET_BUNDLE_EXTRACT_BASE_DIR` says
otherwise. The ingest unit sets that to `/opt/dmarc/data/.net`, because its
sandbox hides the home directory; without it the run dies with **exit 159**
and a message about `DOTNET_BUNDLE_EXTRACT_BASE_DIR` before it has printed
anything else. If a cron job or a hand-written unit ever shows that, this is
why.

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

**You do not have to set this up.** `install.sh` enables `dmarc-backup.timer`
and takes the first copy during the install, so a machine has a backup before
anybody has put anything in it. Nightly at 03:20, into `/opt/dmarc/backups`,
14 kept. [`RUNNING.md`](RUNNING.md#backups) has what it checks and how long it
takes; the short version is that it integrity-checks the **live** database
before copying it, so a database that has begun to corrupt stops the run
rather than filling the retention window with copies of the damage.

```bash
sudo systemctl start dmarc-backup          # whenever you want one now
dmarc backup --to /mnt/elsewhere --keep 30 # or by hand, anywhere
```

`dmarc-health.timer` fails its unit — and so raises an alert through
`dmarc-alert@` — if the newest backup is more than a week old, which is the
timer having stopped rather than one late night.

**Offsite is the part still worth your attention.** A copy on the same disk
survives a bad change and not a dead machine. Set `DMARC_BACKUP_S3` in
`/etc/dmarc-backup.env` and the unit syncs after each run; `AWS.md` has how to
harden that bucket, and the single most important line there is that the
instance role must **not** have `s3:DeleteObject`.

Take the `secrets/` and `keys/` directories off the machine too. The keys only
sign the sign-in cookie; a restore without them means everybody signs in
again, nothing worse.

The secrets directory is encrypted to **this machine and this account**. A
restore onto a new machine cannot read it: the database rows keep working,
but every DNS provider credential has to be entered again. That is the
intended behavior - it is why a stolen backup is not a stolen Cloudflare
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

That builds `dmarc.exe`, `dmarc-linux-x64`, `dmarc-linux-arm64`,
`dmarc-web.zip`, `dmarc-deploy.tar.gz` and `DMARC-Monitor-Windows.zip`, stamps
each with `1.3.0`, and attaches them to a GitHub release along with
`SHA256SUMS.txt`.

**Merging is not releasing.** Nothing on `main` is installable until a tag
builds it, and `bootstrap.sh` fetches the *latest release* - so an install run
straight after a merge gets the previous tag's binaries, with the same version
number it always had and no error to explain the missing work.

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

From the `dmarc-deploy.tar.gz` unpacked in step 2. It copies the scripts to
`/opt/dmarc/deploy`, owned by root, and the agent runs those copies - so when
a later release changes them, run it again from the new tarball.

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
- [ ] It is sandboxed: `systemctl show dmarc-web -p ProtectSystem -p ProtectHome`
      says `strict` and `yes`.
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

`deploy/bootstrap.ps1` is the same script with Windows names, run from an
elevated PowerShell:

```powershell
.\bootstrap.ps1 -HostName dmarc.nextlayersec.io -Email you@nrgtechservices.com
```

What it sets up, and where:

| | Linux | Windows |
|---|---|---|
| Runtime | the distribution's `aspnetcore-runtime-8.0` | a private copy under `C:\dmarc\dotnet`, installed with Microsoft's `dotnet-install.ps1` |
| The app | `dmarc-web.service`, user `dmarc`, sandboxed | Windows service `dmarc-web`, account `NT AUTHORITY\LocalService`, writable only under `C:\dmarc\data` |
| The proxy | Caddy as a systemd service | Caddy as a Windows service through WinSW, ports 80 and 443 opened in Windows Firewall |
| Configuration | `/opt/dmarc/app/appsettings.Production.json` | `C:\dmarc\app\appsettings.Production.json` |
| The collector | `dmarc-ingest.timer`, settings in `/etc/dmarc-ingest.env` | Task Scheduler task `DMARC ingest`, settings in `C:\dmarc\ingest.cmd` (readable by administrators and the service only) |
| The DNS scan | `dmarc-dns.timer`, nightly, enabled from the start | Task Scheduler task `DMARC DNS scan`, nightly, runs `C:\dmarc\dns-scan.cmd`, log in `C:\dmarc\data\dns-scan.log` |
| The certificate | `--make-ingest-cert` via OpenSSL | `-MakeIngestCert` via `New-SelfSignedCertificate` |

Same arguments, PowerShell spelling: `-TenantId`, `-ClientId`, `-Mailbox`,
`-IngestTenantId`, `-IngestClientId`, `-MakeIngestCert`, `-FromDir`, `-NoProxy`.

Caddy needs ports 80 and 443. On a machine with IIS installed they belong to
`http.sys`, and the script stops before installing Caddy and says so; either
`Stop-Service W3SVC` and disable it, or run with `-NoProxy` and put IIS in
front yourself (`Proxy:Behind` is already `true`).

The one genuine difference is the secret store: on Windows it is DPAPI, keyed
to the account that writes the secret. The service runs as `LocalService`, so
a provider token stored from an administrator's console with `dmarc dns set`
is encrypted as that administrator and the service cannot read it. On Windows,
add DNS providers through the Settings page, which stores them as the service.

The Updates page's Install button has no Windows agent yet; update by running
`bootstrap.ps1 -Release <tag>` after stopping the service, or wait for it.

## What has been tested, and what has not

Honesty about the gaps, so you meet them knowing rather than at 11pm.

**Run for real, on every push:** three jobs in `.github/workflows/tests.yml`.
`Install on a fresh Ubuntu` builds the two Linux artifacts the way the
release does and runs `deploy/install.sh` on a clean runner under real
systemd, then checks that the service is active and sandboxed, answers on
loopback and refuses a proxied request, that the cookie keys landed beside
the database, that the update agent's path unit wakes and refuses a bogus
request, and that `rollback.sh` refuses a stamp that was never kept. `One
command on a fresh Ubuntu` and `One command on a fresh Windows` run
`bootstrap.sh` and `bootstrap.ps1` from nothing with everything switched on -
Caddy in front (on `localhost`, with its internal certificate authority),
sign-in against Entra's `common` tenant so the redirect is built for real,
and the collector with a certificate the script makes - and check that a
request through the proxy is redirected to Entra, that the collector reads
its certificate and gets as far as authentication, and that running the
script again only applies configuration. Steps 1 to 6 and the agent in step
9 are not assembled from how the pieces are built; they have run, on both
operating systems.

**Not run:**

- **Amazon Linux 2023.** There is no hosted runner for it. The package names
  and the Caddy steps in step 1 come from Amazon's and Caddy's documentation
  and the live AL2023 package repository, not from a machine; `bootstrap.sh`
  takes the `dnf` path there and the static-binary route for Caddy, and
  neither has been run on Amazon Linux itself.
- **The Caddyfile and the certificate**, and therefore anything reached from
  the internet rather than over loopback.
- **Sign-in through Entra.** The code path is exercised by tests only in its
  not-configured state. Expect to spend an hour on the app registration.
- **`update.sh` end to end**, because it needs a published release to download
  and there is none yet. Its argument handling, backup and swap logic have
  been read and shellchecked, not run against a service.
- **The secret store on Windows** under the service account; only the Linux
  AES-GCM path has run against real provider credentials.
- **Windows Server itself.** `bootstrap.ps1` runs on the hosted Windows
  runner, which is Windows Server 2022/2025 with an administrator shell; a
  hardened domain-joined server with policies of its own has not been tried.

See `OPEN-ISSUES.md` for the rest.
