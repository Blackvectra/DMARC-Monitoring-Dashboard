# What this holds, where it lives, and who can see it

Written to be handed to a client who asks, and to be the factual basis a
lawyer turns into a data processing agreement.

**It is not itself a DPA, a privacy policy or legal advice.** Those need
somebody qualified and they need to name real parties. What follows is the
part only an engineer can supply: exactly what the system collects, where it
goes, how long it stays and who can reach it — checked against the code and
the running database rather than described from memory.

---

## What is collected

DMARC aggregate reports (RFC 7489), TLS reports (RFC 8460), and the DNS records
of the domains being monitored.

### Aggregate reports — the bulk of it

One row per sending source per reporting period:

| | |
|---|---|
| `source_ip` | the address that sent the mail |
| `header_from`, `envelope_from`, `envelope_to` | **domains**, not addresses |
| `dkim_domain`, `dkim_selector`, `spf_domain` | what the message claimed |
| authentication and alignment results | pass / fail per mechanism |
| `message_count` | how many messages that row represents |
| the reporter, and the policy it saw published | provenance |

**No message content. No individual email addresses. No recipients.**

That is a property of the format, not a choice this product made — an
aggregate report is a count of messages grouped by sending source, and the
identifiers in it are domains. Verified against a production database of
23,697 records: **zero** rows contain an `@` in any identifier column.

What it *does* reveal, and what a client is entitled to care about: which
vendors and services send mail on their behalf, the addresses those services
send from, and their authentication posture over time. Commercially sensitive.
Not personal data in the ordinary case.

### Failure (forensic) reports — the sensitive one

The `forensic_reports` table holds `subject`, `return_path`, `message_id` and
`raw_headers`. Those are message headers of real mail, and they **can** contain
personal data: a subject line, a sender, a recipient.

This build parses them. That makes the retention window the control that
matters, so tell clients about this table before turning reporting on rather
than after.

Four things bound what is kept and who sees it:

- **Headers only, never a body.** RFC 6591 lets a receiver attach the whole
  original message. The parser stops at the blank line that ends the headers,
  so a message body is never written to the database and there is nothing
  stored for anybody to reveal later.
- **30 days, not 400.** Failure reports are pruned on their own, shorter clock,
  and `dmarc prune` refuses a policy that would let them outlive the aggregate
  data.
- **Reading them needs the Tech role.** Everyone signed in can see that a
  report arrived, from what address, what failed and whether it was delivered.
  The subject line and the headers are hidden below Tech — which is where a
  customer's own login normally sits.
- **Every look is in the audit log.** Revealing the headers of one report
  writes a `forensic.read` entry naming who did it and which domain, so "who
  read this customer's mail" is a question with an answer.

In practice the table stays small. Google, Microsoft and Yahoo do not send
failure reports at all, so publishing `ruf=` produces a trickle from a handful
of smaller receivers rather than a copy of the mail stream.

### Credentials

Never in database rows. The mailbox certificate is a file on disk read by the
service account; DNS provider credentials are held by an OS-level secret store
and the database keeps only an opaque `credential_ref` pointing at it. Nothing
in a backup or an export can be used to authenticate as anybody.

---

## Where it lives

| | |
|---|---|
| The database | SQLite, on the machine you run it on: one file for the organization - clients, domains, users, the audit log - and one per client for that client's reports and DNS history, `0600` in a `0700` folder ([CLIENT-FILES.md](CLIENT-FILES.md)) |
| Backups | `0600`, in a `0700` directory, same machine unless you configure offsite |
| Offsite copies | only if `DMARC_BACKUP_S3` is set — your bucket, your region, your keys |
| Exports | `0600`, only when somebody runs `dmarc export --out` |

**Nothing is sent anywhere else.** There is no telemetry, no vendor backend,
no third-party analytics. The only outbound connections are: the mailbox being
collected, DNS queries for the domains being monitored, HTTPS fetches of
`mta-sts.<domain>` policy files, the DNS provider's API when a fix is applied,
and GitHub for update checks.

That is the substantive difference from a hosted DMARC platform, and it is
worth stating plainly to a client: with dmarcian, PowerDMARC or Sendmarc their
report data is processed on the vendor's infrastructure under the vendor's
retention. Here it is on infrastructure you control and they can ask you to
point at.

### Encryption

| | |
|---|---|
| In transit | HTTPS everywhere: Graph, DNS-over-HTTPS where used, MTA-STS fetches, the web app behind TLS |
| At rest | **the deployment's job, not the application's** — EBS encryption on AWS, SSE-KMS on the S3 bucket |
| The file itself | optional, via `age` or `gpg` before the offsite sync — see [AWS.md](AWS.md#encrypting-the-file-itself) |

The application does not encrypt its own database. That is a deliberate
position, not an oversight: full-disk and bucket-level encryption are the
layers that actually protect a file at rest, and a key held next to the
ciphertext protects against a stolen disk and nothing more. If a client
requires application-level encryption specifically, say that it is not built
rather than implying the box being encrypted is the same thing.

---

## How long it is kept

Enforced weekly by `dmarc prune`, not aspirational:

| | |
|---|---|
| Aggregate and TLS reports | **400 days** — thirteen months, so any month has last year's beside it |
| Forensic reports | **30 days** — the shortest window, because it is the one that could hold personal data |

Both are configurable, and a policy where forensic outlives aggregate is
refused. Domains, clients and organizations are never deleted by retention —
only the reports age out.

For context: hosted platforms commonly retain 90–180 days. This keeps *more*
aggregate history and *less* forensic.

---

## Who can see it

| | |
|---|---|
| **Organization** | a security group. Its people see its clients and domains and nothing else. |
| **Roles within one** | viewer reads; operator also assigns, imports and applies DNS fixes; admin also runs settings |
| **Client login** | a group scoped to one client, read only — the customer's own view |
| **Master group** | named in configuration, sees every organization |

The organization boundary is enforced in queries, not in the UI. Every domain
lookup is scoped by organization; a two-organization test database is part of
the test suite specifically to prove one cannot read the other's selectors,
report counts or domain list.

With no sign-in configured the app binds to loopback and refuses everything
else. `Auth:AllowLocalModeRemotely` removes that guard **without adding
authentication** — never set it on a machine holding client data.

### What is recorded

An audit log holds who did what and when, for DNS changes, retention runs and
administrative actions. It is per organization and visible to that
organization's admins.

---

## If you are asked the standard questions

**"Where is our data?"** On a named machine, in a named region, which you can
show them. Not on a vendor's platform.

**"Who else can see it?"** Your named staff, by group membership, scoped to
their organization. Optionally their own people, read only, scoped to them.

**"How long do you keep it?"** 400 days aggregate, 30 days forensic, enforced
weekly by a job that writes to an audit log.

**"Is it encrypted?"** In transit yes. At rest, at the volume and bucket
level — say which, and do not claim application-level encryption.

**"Can we have it deleted?"** Yes, and it is one command:

    dmarc client erase --client acme-corp                       # what would go
    dmarc client erase --client acme-corp --apply --confirm acme-corp --by matthew

It removes the client and everything belonging to them and then **proves
it**. Their reports, records, selectors and DNS history are a database file of
their own, which is deleted and checked to be gone; their domains, contacts and
settings are rows in the organization's database, and every table there
carrying a `client_id` is checked afterwards. Anything left behind in either
takes the whole erasure back rather than leaving a half-erased customer and a
confident message.

The table list is read from the schema rather than written down, because the
number of tables only goes up. A stale list would leave a table full of an
erased customer's data that nobody counted.

What survives, deliberately: the **audit log** entry recording that you did it,
who asked, and how many rows went. It carries the client's name and the counts
and none of the erased data. Proving a request was honoured is the other half
of honouring it.

**Backups are the honest caveat.** Erasing from the live database does not
reach the nightly copies. With the default 14 kept, the last copy ages out
about two weeks later, and any offsite sync carries its own retention on top.
The command prints that date every time it runs. **Give the customer that
timeframe rather than saying "it is gone".**

Nor does it reach the whole copies of the database kept beside it on purpose:
`dmarc.pre-0019.db` from the upgrade that gave each client a file,
`update.sh`'s copy from each update, and whatever a restore or rollback moved
aside. Nothing prunes those - they are there to be gone back to - so the
command lists every one it finds. Delete them once they are no longer needed,
and before telling a customer their data is gone.

**"Do you have SOC 2?"** No. Neither does a self-hosted install of anything.
If a client's procurement requires it, that is an argument for a platform that
has one, and it is worth saying so rather than losing the account later.

---

## Before selling this to anybody

This document describes a self-hosted tool honestly. **Running it as a service
other people sign up for is a different undertaking** and this document does
not cover it. At minimum that needs, before the first paying customer:

- a real DPA and privacy policy, drafted by somebody qualified
- a stated legal basis and a controller/processor position per customer
- breach notification obligations you can actually meet, with a timeframe
- a backup retention story that matches what you promise on erasure
- an answer on sub-processors (AWS is one)
- and, honestly, an answer on SOC 2 — because enterprise procurement will ask

See [COMPARISON.md](COMPARISON.md) for where this sits against the hosted
platforms today.
