# On AWS, from nothing to signed in on your phone

A start-to-finish runbook for one EC2 instance that you can reach from the
office, from home and from a phone, with Microsoft sign-in, MFA and passkeys.

[`DEPLOYING.md`](DEPLOYING.md) is the general deployment guide and covers the
install itself, the proxy, the ingest timer and backups on any machine. This
page is the AWS-specific part around it, plus the authentication layer, and it
links out rather than repeating.

**What you end up with**

- `https://dmarc.nextlayersec.dev` — reachable from anywhere, on anything with
  a browser.
- No SSH port open, at all. Console access through AWS Systems Manager.
- No password belonging to this product. Sign-in is Entra, so MFA, passkeys,
  conditional access and revoking somebody are all things your tenant already
  does.
- About **$21–23 a month**.

---

## Decide two things before you start

**The hostname.** A subdomain of something you already own —
`dmarc.nextlayersec.dev`. Do not buy a domain for this. The name goes in three
places (the DNS record, the Caddy config, and the Entra redirect URI) and
changing it later means touching all three.

**Who signs in.** A security group in Entra, not a list of individuals — you
want to add somebody by putting them in a group. Group-based assignment needs
Entra ID **P1**, which is included in Microsoft 365 Business Premium and E3.
On a free tenant you assign people one at a time and everything else here
still works.

---

# Part 1 · The AWS side

## 1.1 Region

**us-east-2 (Ohio)** unless you have a reason. Closest major region to North
Dakota, cheap, everything available. Whatever you pick, stay in it — half the
steps below are region-scoped and a resource in the wrong one is invisible
rather than broken, which is worse.

## 1.2 An IAM role, so you never open SSH

This is the step people skip, and it is the one that removes the largest
attack surface on the box.

**IAM → Roles → Create role**

- Trusted entity: **AWS service** → **EC2**
- Permissions: **`AmazonSSMManagedInstanceCore`**
- Name: `dmarc-monitor-ssm`

That is the whole role. It lets you open a root shell on the instance from the
AWS console or the CLI, over the instance's *outbound* connection, with no
inbound port, no key pair and no bastion. Access is IAM, so it is already
covered by whatever MFA your AWS account enforces, and every session can be
logged.

The alternative — port 22 open to the internet, or to "my IP" which changes
every time you move — is how these boxes get found.

## 1.3 The security group

**EC2 → Security Groups → Create**, name it `dmarc-monitor`.

**Inbound** — three rules, and nothing else:

| type | port | source | why |
|---|---|---|---|
| HTTPS | 443 | `0.0.0.0/0` | the actual app |
| HTTP | 80 | `0.0.0.0/0` | Let's Encrypt's challenge, and the redirect to HTTPS |
| HTTPS | 443 | `::/0` | same, if you enable IPv6 |

**No SSH rule. None.** If you are staring at this thinking it should be there,
re-read 1.2.

**Outbound** — leave the default **all traffic**. The instance needs it:

- 443 to Microsoft Graph, for the collector
- 443 to Let's Encrypt
- **443 to arbitrary hosts**, because `dmarc check` now fetches MTA-STS policy
  files the way a sending mail server does. Lock egress down and those checks
  come back as "could not be read" — correctly, and unhelpfully.
- 53 for DNS, and 80/443 for `apt`
- 443 to the SSM endpoints, which is what makes 1.2 work

### "Should I restrict 443 to my office IP?"

No. You asked for work, home and phone. A phone's address changes on every
cell handover and every café. You would spend your life editing a security
group and eventually give up and open it.

**The gate is authentication, not the network.** Open 443, put Entra in front
of it, and require a passkey. That is a better control than an IP allowlist
and it works from a car park.

## 1.4 Launch the instance

**EC2 → Instances → Launch an instance**

| | |
|---|---|
| Name | `dmarc-monitor` |
| AMI | **Ubuntu Server 24.04 LTS**, and note the architecture |
| Type | **`t3.small`** (x86, 2 GB). `t4g.small` (ARM) also works and costs ~$3/month less |
| Key pair | **Proceed without a key pair.** You are using SSM |
| Network | Default VPC, a public subnet, **auto-assign public IP enabled** |
| Security group | the `dmarc-monitor` one from 1.3 |
| Storage | **20 GB gp3**, and **tick Encrypted** |
| Advanced → IAM instance profile | **`dmarc-monitor-ssm`** |

**Tick Encrypted.** It is one checkbox at launch and a snapshot-restore-detach-
reattach exercise afterwards, so decide now. It costs nothing, it is invisible
in use, and without it every client's data sits in plaintext on a volume whose
physical life you do not control. If you ever answer a security questionnaire,
this is question one.

Set it as the default while you are there so you cannot forget on the next
instance: *EC2 → Account attributes → EBS encryption → Always encrypt new EBS
volumes.*

**On storage:** the database is small and now stays small — retention is
enforced weekly (`dmarc prune`, 400 days of aggregate data, 30 of forensic).
A sixteen-domain estate is tens of megabytes. 20 GB is mostly headroom for the
OS, logs and a local backup copy.

**On instance type:** 2 GB is the floor. The web app is a Blazor Server app and
holds a little state per open browser tab; 1 GB works until two people have it
open and then it does not.

**x86 or ARM.** Both are built and both are installed end to end by CI on
every change — the whole `install.sh` run, the service answering, the timers,
a backup and a health check, on each architecture. `t3.small` is what this
page uses because it is the ordinary choice and because every third-party
thing you might add later (an agent, a package, a container) has an x86 build
without you checking. `t4g.small` is ARM, saves about $3 a month, and is a
supported path rather than an experiment; if you take it, the only difference
is that you download `dmarc-linux-arm64` instead — `bootstrap.sh` picks the
right one from `uname -m` on its own.

**One `t3` billing note.** `t3` instances default to **unlimited** CPU-credit
mode, which means a sustained CPU spike bills extra rather than throttling.
This workload does not get near the baseline — a few browser tabs and an
hourly collector — so in practice you will not see it, but it is the one line
on a `t3` bill that surprises people. *EC2 → the instance → Actions →
Instance settings → Change credit specification* turns it off if you would
rather be throttled than billed.

## 1.5 An Elastic IP

**EC2 → Elastic IPs → Allocate**, then **Associate** it with the instance.

Without one, the public IP changes every time the instance stops and starts,
and your DNS record quietly points at somebody else's machine.

Since 2024 AWS charges for every public IPv4 address (~$3.60/month) whether
it is elastic or not, so this costs nothing extra while it is attached. An
Elastic IP you allocate and then *leave unattached* is billed — if you tear
this down, release it.

## 1.6 DNS

At whoever hosts `nextlayersec.dev`:

```
dmarc    A    <the Elastic IP>    TTL 300
```

Keep the TTL low until it is working. Check it has propagated before the next
part, because Caddy will try to get a certificate and Let's Encrypt has rate
limits you can hit by retrying a broken name:

```
dig +short dmarc.nextlayersec.dev
```

---

# Part 2 · Install

## 2.1 Get a shell

**EC2 → Instances →** select it **→ Connect → Session Manager → Connect.**

A root shell in the browser, no port open. If the Connect button is greyed
out, the instance has not registered with SSM yet — give it two minutes after
first boot, then check the IAM role from 1.2 is actually attached.

From your own machine instead, if you have the AWS CLI:

```
aws ssm start-session --target i-0123456789abcdef0 --region us-east-2
```

## 2.2 One command

```
sudo -i
curl -fsSL https://raw.githubusercontent.com/Blackvectra/DMARC-Monitoring-Dashboard/main/deploy/bootstrap.sh \
  | bash -s -- --host dmarc.nextlayersec.dev --email you@nextlayersec.dev
```

That installs the CLI and the web app, writes the systemd units, installs and
configures Caddy, and gets a certificate. [`DEPLOYING.md`](DEPLOYING.md) has
what it does step by step and how to do it by hand.

> **It installs the latest *release*, not `main`.** The script itself comes
> from `main`, which is why the URL says so, but the binaries it downloads are
> whichever version was last tagged. Merging a change does not produce
> anything installable — pushing a `v1.2.3` tag does, and that is what builds
> and attaches the files this line fetches. So: tag first, then run this, or
> you will install last month's build and spend an afternoon wondering where
> a feature went. `--release v1.2.3` pins a specific one.

It also enables four scheduled jobs from the first day, and leaves a fifth
switched off until you can fill it in:

| timer | what |
|---|---|
| `dmarc-dns.timer` | nightly — reads each domain's published records |
| `dmarc-backup.timer` | nightly at 03:20 — a verified copy of the database, 14 kept |
| `dmarc-health.timer` | 09:10 and 21:10 — asks whether collection has quietly stopped |
| `dmarc-prune.timer` | weekly — applies the retention window |
| `dmarc-ingest.timer` | **not** enabled — it waits until you give it a certificate and a mailbox (Part 6) |

The install also takes the first backup itself rather than leaving it until
03:20, so there is a copy before you have put anything in — and so the health
check is green from the start instead of failing on the evening of install day
over a backup that has not had a chance to run yet.

## 2.3 Check it before you go further

```
systemctl status dmarc-web
curl -fsS -o /dev/null -w '%{http_code}\n' https://dmarc.nextlayersec.dev
```

A `403` from the outside at this point is **correct and is the point**. With no
Entra sign-in configured the app refuses any request that came through a proxy,
whatever its address, and says so in the body. It will not serve your data to
the internet because you opened a port.

Do not set `Auth:AllowLocalModeRemotely` to get past this. That switch removes
the guard *without adding authentication* — anyone who can reach the port reads
every customer's mail data. Configure sign-in instead; that is the next part.

---

# Part 3 · Microsoft sign-in

Follow [`DEPLOYING.md` §5](DEPLOYING.md#5-sign-in) for the app registration.
The short version, and the two things that catch everybody:

- Redirect URI **Web** → `https://dmarc.nextlayersec.dev/signin-oidc`, plus
  `…/signout-callback-oidc`.
- Under *Implicit grant and hybrid flows*, tick **ID tokens**. This app signs
  people in without a client secret, and Entra refuses that flow until the box
  is ticked. The error names `response_type` and does not mention the box.

Then **Enterprise applications → DMARC Monitor**, in this order:

1. **Permissions → Grant admin consent.**
2. **Properties → Assignment required = Yes.**
3. **Users and groups →** add your group.

The order matters. Once assignment is required, people can no longer consent
for themselves, and a first sign-in without step 1 dies on "Need admin
approval".

Put the tenant and client IDs in config and restart. Now the same URL signs you
in instead of returning 403.

---

# Part 4 · MFA and passkeys

**The product has no password and no MFA of its own.** Every identity decision
is Entra's. That is deliberate: this is a monitoring tool that should not be in
the business of storing credentials, and it means MFA, passkeys, conditional
access, device compliance and offboarding are whatever your tenant already
does.

So everything below is Entra configuration, not application configuration.

## 4.1 Turn the passkey method on

**Entra admin center → Protection → Authentication methods → Policies →
Passkey (FIDO2)**

- **Enable**: Yes
- **Target**: your DMARC group, or all users

Two settings on that page decide whether the thing in your pocket is allowed
to work:

- **Enforce attestation** — leave **off** unless you are issuing hardware keys
  and want to prove the model. On, it refuses passkeys that cannot attest,
  which includes some platform and third-party ones.
- **Enforce key restrictions** — if this is **on**, only the AAGUIDs in the
  list are accepted, and *everything else is silently refused at registration*.
  This is the single most common reason "passkeys are enabled but my phone will
  not register".

  If you leave key restrictions on, you must add the AAGUID of whatever you
  intend people to use — passkeys in Microsoft Authenticator have their own
  per-platform values. Take them from Microsoft's current documentation rather
  than from memory or a blog post; they are exact values and a wrong one fails
  in a way that looks like the feature being broken.

  Simplest working answer for a small team: **key restrictions off.**

## 4.2 Register one

Each person, once, at **<https://aka.ms/mysecurityinfo>** → *Add sign-in
method* → **Passkey**.

| where they are | what they get |
|---|---|
| Phone | Passkey in **Microsoft Authenticator** — face or fingerprint, and it is the one that makes phone access painless |
| Windows laptop | **Windows Hello** — the laptop itself becomes the key |
| Mac / iPhone | Touch ID / Face ID, subject to 4.1's key restrictions and your tenant's support for third-party providers |
| Hardware | A YubiKey or similar, if you want something that survives losing the phone |

**Register two.** A passkey on one device and one more — a second device or a
hardware key. A single passkey on a single phone is one dropped phone away from
a support call to yourself.

## 4.3 Actually require it

Enabling passkeys does not require them. Two ways, depending on licensing:

### With Entra ID P1 — Conditional Access (what you want)

**Protection → Conditional Access → New policy**

| | |
|---|---|
| Users | your DMARC group |
| Target resources | **DMARC Monitor** (the enterprise app) |
| Grant | **Require authentication strength → Phishing-resistant MFA** |

**Phishing-resistant** is the one that matters. Plain "require MFA" accepts a
push notification or a code, both of which can be phished or fatigued.
Phishing-resistant accepts passkeys, hardware keys, Windows Hello and
certificate-based auth, and nothing else.

Create it in **Report-only** mode first, sign in once, check the sign-in log
says it would have applied, then switch it to **On**. A conditional access
policy scoped wrongly and set live is how people lock themselves out of their
own tenant — **exclude a break-glass admin account from every policy you
write**, and keep its credentials somewhere physical.

Scoping the policy to this one app rather than to everything is deliberate: it
lets you require a passkey for the DMARC monitor without renegotiating how the
whole company signs in to Outlook.

### Without P1 — Security Defaults

**Entra admin center → Identity → Overview → Properties → Security defaults →
Enabled.**

That enforces MFA for everybody in the tenant through Microsoft Authenticator.
It is free, it is all-or-nothing, and it **cannot require a passkey
specifically** — people can still register a passkey and use it, you just
cannot insist on it. It is a reasonable floor.

Security Defaults and Conditional Access are mutually exclusive: turning on any
CA policy requires Security Defaults to be off.

## 4.4 Prove it

Sign out, open `https://dmarc.nextlayersec.dev` on your phone on **mobile
data** — not the office wifi, which may be trusted by some other policy — and
sign in with the passkey. If it asks for a password and then a code, the CA
policy is not applying; check the **sign-in logs**, which name the policy that
did or did not fire.

---

# Part 5 · Work, home and phone

There is nothing more to configure. It is one HTTPS URL and one identity.

| | |
|---|---|
| Office | the URL |
| Home | the URL |
| Phone | the URL. The layout collapses for narrow screens |
| Somebody else's laptop | the URL, and the passkey means you are not typing a password into it |

**No VPN.** A VPN here would buy you nothing that the passkey does not already
buy, and would stop the phone working from anywhere useful.

**One honest caveat about phones.** The web app is Blazor Server: the page
holds a live connection to the server. Lock the phone or lose signal in a lift
and it shows *"Attempting to reconnect"* and then needs a refresh. It is not
broken, and it is a real difference from an app that reloads state on every
page. Reports and exports are ordinary downloads and are unaffected.

---

# Part 6 · Once it is up

## Point the collector at the mailbox

The last piece, and a separate app registration from the sign-in one — a
certificate rather than a secret. [`INGEST-SETUP.md`](INGEST-SETUP.md) has it.

**Read the part about the application access policy before the first run.**
`Mail.ReadWrite` as an application permission is tenant-wide by default: it
reads *every* mailbox until you restrict it to one. That restriction is a
PowerShell command against Exchange Online, it takes a minute, and it is not
optional.

Once it works, and once you have watched it for a few runs, add
`DMARC_DELETE=permanent` to `/etc/dmarc-ingest.env` so the mailbox stops
filling up.

## Backups

Two layers, and they fail differently — which is why both.

**`dmarc backup`, nightly.** Enabled by `install.sh`, which also takes the
first copy during the install so there is one before you walk away. It
integrity-checks the live database, writes a consistent copy (`0600`, in a
`0700` directory) and keeps 14. See [`RUNNING.md`](RUNNING.md#backups). This is
the one that survives a bad change, and the only one that tells you the
database has started to corrupt.

**`dmarc health`, twice a day.** Also enabled by `install.sh`. It notices a
collector that has quietly stopped — the failure this product is worst at
showing you on its own, because every screen goes on displaying the figures
from before it stopped and those look fine — and it notices backups stopping.

**It is deliberate about which of those fails the unit**, because that is what
turns into an alert. Something *broken* exits 1, the oneshot unit fails, and
`OnFailure=` starts `dmarc-alert@`. Something merely *worth knowing* prints and
exits 0, so nothing is sent: a check that pages every night over one late job
is a check somebody mutes, and then the real one arrives into a muted channel.

| what it finds | unit fails? |
|---|---|
| Nothing stored for an organization in 36 hours | **yes** |
| No backups at all | **yes** |
| Newest backup older than 7 days — the timer has stopped | **yes** |
| Newest backup 2–7 days old — a late job | no, prints only |
| Domains gone quiet for a week while others kept arriving | no, prints only |
| A domain name held by two organizations | no, prints only |

`/etc/systemd/system/dmarc-alert@.service` is where a failed unit becomes mail,
Slack or SNS, and until you edit it nothing is sent anywhere.

**EBS snapshots, daily.** *EC2 → Lifecycle Manager → Create lifecycle policy*,
target by tag, daily, keep 7. Pennies. This is the one that survives losing the
instance. Snapshots are crash-consistent, which is acceptable for SQLite in WAL
mode — and the `dmarc backup` copy sitting on the volume is the clean one, so
the snapshot carries both.

### Offsite, to S3

A backup on the same instance protects against a bad change, not against losing
the instance. Set `DMARC_BACKUP_S3` in `/etc/dmarc-backup.env` and the unit
syncs after each run.

Four things make that bucket safe rather than just remote:

**Block Public Access — all four settings, at the bucket.** The default is on
for new buckets; confirm it rather than assume it.

**Default encryption: SSE-KMS** with a customer-managed key. SSE-S3 is fine and
simpler; KMS gives you an audit trail of every decrypt in CloudTrail and a key
you can revoke, which is the difference when somebody asks how you would
contain a breach.

**Versioning on, plus a lifecycle rule** to expire noncurrent versions after
(say) 90 days. Without versioning, one bad sync or one `rm` replicates the
mistake offsite at 03:20.

**Do not grant the instance `s3:DeleteObject`.** This is the one people miss.
An instance role that can delete is an instance role that a compromise can use
to wipe every offsite backup you have. `aws s3 sync` without `--delete` never
needs it:

```json
{
  "Effect": "Allow",
  "Action": ["s3:PutObject", "s3:ListBucket", "s3:GetObject"],
  "Resource": [
    "arn:aws:s3:::your-bucket",
    "arn:aws:s3:::your-bucket/dmarc/*"
  ]
}
```

For backups you genuinely cannot afford to lose, **S3 Object Lock in
governance mode** makes them undeletable for a retention period even by you.
That is the control that survives ransomware.

### Encrypting the file itself

SSE-KMS protects the object in S3. It does not protect it from anybody who can
read it *through* S3 with your credentials, and it means AWS holds the
plaintext path. If your threat model or a client contract needs the file
encrypted before it leaves the box:

```bash
# /etc/dmarc-backup.env
DMARC_BACKUP_S3=s3://your-bucket/dmarc
```

then add an encrypt step ahead of the sync in
`/etc/systemd/system/dmarc-backup.service`:

```
ExecStartPost=-/bin/sh -c 'for f in "$DMARC_BACKUP_DIR"/*.bak; do [ -f "$f.age" ] || age -r "$AGE_RECIPIENT" -o "$f.age" "$f"; done'
```

and sync only `*.age`. **Keep the private key off the instance.** A decryption
key stored next to the ciphertext protects against a stolen disk and nothing
else — and a backup you cannot decrypt is not a backup, so test a restore
before you rely on it.

## What it costs

| | ~monthly |
|---|---|
| `t3.small`, on all the time | $15 |
| 20 GB gp3 | $1.60 |
| Public IPv4 | $3.60 |
| Snapshots | <$1 |
| | **≈ $21–23** |

On `t4g.small` (ARM) the first line is $12 and the total ≈ $18–20.

Stop the instance when you are not using it and you pay only for the disk and
the address — about $5 — which is the right shape while you are still testing.

---

# When it does not work

| symptom | cause |
|---|---|
| Connect button greyed out in the console | IAM role from 1.2 missing, or the instance has not registered yet. Wait two minutes |
| Caddy cannot get a certificate | DNS not propagated, or port 80 closed. Let's Encrypt needs to reach it |
| **403 with a wall of text** from outside | Correct, before sign-in is configured. Part 3 |
| Sign-in fails naming `response_type` | The **ID tokens** box in the app registration. Part 3 |
| "Need admin approval" on first sign-in | Grant admin consent *before* setting assignment required |
| Passkey will not register | **Key restrictions** in 4.1. This one costs people an afternoon |
| Signed in but told to use a code, not a passkey | The CA policy is not applying. Check the sign-in logs, which name the policy |
| Dashboard empty | Nothing collected yet. `dmarc import` a folder to see it populated |
| `dmarc-health` shows as failed | It found something, which is its job. `journalctl -u dmarc-health -n 40` names the fault and the fix |
| `dmarc-backup` failed | `journalctl -u dmarc-backup -n 30`. A full disk is the usual cause; a failed integrity check is the one to act on today |
| Installed but an old version | `bootstrap.sh` installs the latest **tag**, not `main`. 2.2 |
| MTA-STS checks say "could not be read" | Outbound 443 is restricted. 1.3 |
| `"Attempting to reconnect"` on a phone | Blazor circuit dropped. Refresh. Part 5 |

---

# The short version

0. Tag a release (`v1.2.3`) and wait for it to build — step 5 installs the
   latest tag, not `main`
1. IAM role with `AmazonSSMManagedInstanceCore`
2. Security group: 443 and 80 in, nothing else, all out
3. `t3.small`, Ubuntu 24.04, 20 GB **encrypted**, no key pair, role attached
4. Elastic IP → DNS A record
5. Session Manager → `bootstrap.sh --host … --email …`
6. Entra app registration — **tick ID tokens**, consent, assignment required
7. Passkey method on — **key restrictions off**
8. CA policy: that app, **phishing-resistant MFA**, report-only first
9. Register a passkey on the phone and one more
10. Collector, with the application access policy in place first
