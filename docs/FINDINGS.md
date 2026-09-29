# Findings

What the product finds, kept as one row per thing that is wrong however many
nights see it, with what its source last saw and what a person decided kept
apart. DNS drift, a domain whose reports stopped arriving, and a change this
product applied that has not yet been shown to have taken are all findings;
the Operations page, `dmarc findings`, the webhook and the ConnectWise PSA all
read the same rows.

This is the reference. The design and what remains are issue 12b in
[`OPEN-ISSUES.md`](OPEN-ISSUES.md).

---

## The model

**Two states, never merged.**

| | values | moved by |
|---|---|---|
| `source_state` | `active` — the source still sees it; `resolved` — a successful observation no longer shows it, for as long as the type requires; `unknown` — the last observation of its scope failed, so nothing is known | only the source that raised it |
| `analyst_state` | `unreviewed`, `investigating`, `action_required`, `benign`, `accepted_risk`, `closed` | only a person, on the Operations page |

A decision never moves the source's state: closing a finding whose record is
still wrong leaves the record wrong, and the next observation says so. A
source never moves a decision either: a finding that comes back after being
resolved reopens the same row, with its history, and asks to be reviewed
again.

**Failed collection is unknown, not resolved.** When a source cannot observe
a scope — the DNS lookup failed, the collector's last run failed, nothing has
been stored for an organization in 36 hours — every finding it has open there
becomes `unknown`, and none is cleared. A broken collector is not a condition
that went away. Silence is evidence only when somebody was listening.

**Resolution follows the type.** A DNS finding resolves on one successful
read that matches what was published before the change (`expected_ref`); a
reporting-stopped finding needs three consecutive observations with reports
arriving. The count restarts if the condition is seen again in between.

**Identity** is (`tenant_id`, `source_id`, `client_id`, `dedup_key`), unique.
A source that sees the same condition again updates `last_observed_at` and
`observation_count` and never inserts a second row. The key is the *thing*,
not the observation: a DMARC record that goes from loosened to removed is one
finding whose type and severity moved, and one ticket.

**Evidence stays where it lives.** A finding carries `evidence_ref`, a pointer
at the row in the client's own file that holds the record text or the report
(`drift:<id>`, `report:<id>`, `change:<id>`), and `expected_ref`, a hash of
what a resolving read has to serve. The organization's database holds no
record value and no report body, so a copy of it says what was found and not
what the client publishes. The title is a derived line (`DMARC: p=quarantine
→ p=none.`, `SPF: a term was removed, -all → ~all.`), never the record: a
policy, a percentage, an alignment mode and the `all` qualifier are
enumerations; an address or a mechanism is the record, and the drift event in
the client's file keeps the full sentence for the DNS changes page.

---

## The tables

All in the organization's database ([`CLIENT-FILES.md`](CLIENT-FILES.md)):
findings are operational state *about* a client, like the audit log, not the
client's data. They carry `client_id`, so `dmarc client erase` removes them
and a client moved to another organization takes them along.

| table | |
|---|---|
| `findings` | the current state: identity, type and rule, severity, title, the two states, the remediation stage, `first_observed_at`, `last_observed_at`, `observation_count`, `absent_count`, `reopened_count`, `evidence_ref`, `expected_ref`, `related_finding_id`, `payload_json` |
| `finding_events` | append-only: what happened to it, when, by whom (a source's id or a person), from what to what, with a note. This is the timeline the page shows and what a destination is told about |
| `finding_exceptions` | a decision to live with a finding for a while: reason, approver, compensating control, approved date, review date (required), optional expiry. One open per finding |
| `finding_sources` | one row per engine per client (or per organization), with its last attempt, last success, last failure and last error. Health is computed when read, never stored |

Migration `0022` adds them; the client-file `alerts` table nothing ever wrote
to is dropped by client migration `0002`.

---

## Sources and their health

| source | raises | records a run |
|---|---|---|
| `dns-scan` | drift findings, from the rules in `DnsDrift.cs` | after every nightly scan, per client: healthy when every domain read, degraded naming the domains that did not |
| `reports` | `REPORTING_STOPPED` | after every `dmarc ingest` (success when the mailbox was read; the error when not) and after every completed import |
| `remediation` | `REMEDIATION_PENDING_VERIFICATION` | not on its own: verified by the DNS scan's reads and by the reports |

Health is one of `healthy`, `degraded` (the last attempt failed but a recent
one succeeded), `stale` (nothing within 1.5× the expected cadence), `failed`
(the last attempt failed and nothing succeeded within the window) or
`unknown` (never a success). An engine that has never reported is not shown
as healthy anywhere: the Operations page says so, and so does `dmarc health`.

---

## The types

Every type has a source that says what identifies it, where its evidence is,
what resolves it and how severity is decided (`FindingTypes.cs`). A type
nothing raises is not defined, however plausible it sounds.

| type | source | identity | resolves when |
|---|---|---|---|
| `DNS_DRIFT` | dns-scan | domain and record type | one read serves the record as it was before the change |
| `DMARC_POLICY_WEAKENED` | dns-scan | the DMARC record | as above; critical: `p` or `sp` loosened, a report address lost, the record removed or unparseable |
| `DMARC_POLICY_CHANGED` | dns-scan | the DMARC record | as above; warning when tightened, `pct` lowered or alignment changed |
| `SPF_INVALID` | dns-scan | the SPF record | as above; critical: removed, unparseable, or published twice |
| `SPF_CHANGED` | dns-scan | the SPF record | as above; warning for a term removed or `all` weakened |
| `REPORTING_STOPPED` | reports | the domain | reports cover the domain again on three consecutive observations, with collection healthy throughout |
| `REMEDIATION_PENDING_VERIFICATION` | remediation | the applied change | the change is verified (below), rolled back, or fourteen days pass after DNS verification |

Deferred, with the reason, in issue 12b: `dkim_selector_missing`,
`mta_sts_failure`, `tls_failure`, the report-derived and anomaly types, and
`unknown_sender`, which waits for sender approval.

### Reporting stopped

A domain is quiet after seven days without a report covering it. It is
raised only if it reported regularly before that — in four of the five weeks
up to its last report — so a parked domain a receiver mentions monthly never
fires. Critical when the current DNS reading shows the DMARC record no longer
asks for reports; warning otherwise. The evidence is the domain's newest
report.

Nothing is observed at all, and open findings are marked unknown, when the
collector has not recorded a run, its last run failed, none succeeded within
36 hours, or nothing has been stored for any of the organization's domains in
36 hours — that last is the mailbox, not the domains, and `dmarc health` is
what says so.

---

## Verification, which is where DNS is different

A DNS edit is not a remediation. The provider accepting it, DNS serving it
and the receivers behaving as intended are three different facts, and a
change applied from the Fix page is a finding until the last of them:

| stage | reached when |
|---|---|
| `dns_pending` | the provider accepted the write. A day on with DNS still not serving the value, the finding is a warning |
| `dns_verified` | the verify poll after applying, or the nightly read, serves the applied value |
| `effectiveness_pending` | for a DMARC policy change: waiting for a receiver's report covering a period after the change whose published policy (`p`, `sp`, `pct`, `adkim`, `aspf`) is the one applied |
| resolved | that report arrives, named by receiver; or fourteen days after DNS verification with none, as *verified by DNS only*, and the history says so. A change of a type with no report evidence to wait for resolves when DNS serves it |

The drift finding a change answers is told what the record should now serve
(an `ExpectedChanged` event on it), so drift and change resolve on the same
read. A rollback withdraws the change's finding as *not verified* and puts the
drift's expectation back. The value this product wrote arriving in DNS is not
observed as drift.

**Open point.** A read served from a cache before the old TTL expires
verifies nothing. The verify poll uses its own resolver with no cache, and
the nightly read is hours later; whether either asks the domain's
authoritative servers directly is not yet confirmed, and until it is, DNS
verification is a read past the caches this product controls, not past every
cache.

---

## Exceptions

An exception takes a finding out of the queue and changes nothing about
observation. It needs all four: a reason, who approved it, what compensates
for it, and a date it is due back for review; an expiry is optional. The
source keeps observing the finding throughout, so an expired exception
resurfaces a finding its source still sees, with its history intact — and
one the source has since resolved stays resolved. Recording, ending and
expiring are all events on the finding and entries in the audit log.

---

## Where it is read

**Operations**, in the web app, answers what a morning asks, in order: what
broke (open findings at warning or above nobody has closed, called benign or
excepted), what changed (every change on a finding in the window), what
needs review, awaiting verification, excepted (with the date each is due
back), and the engines. A finding opens to its history and the decisions a
person may make. It is a detection and verification console, not a work
queue: nothing is assigned or given a deadline here, because the ticket
lives in the PSA.

**`dmarc findings list`** prints what is open and wants a person, worst first,
and exits 1 while a critical finding does — the shape a pipeline polls.
`--all` lists everything.

**`dmarc findings observe`** is the nightly step after the DNS scan: the
reports source, the remediation deadline, and expired exceptions.

**`dmarc health`** reads the engines' own run records (failed is broken now;
not run in its window is a weakness; never run is said rather than shown as
health) and names an organization's open critical findings as a check.

**Destinations** — the signed webhook and ConnectWise — are told about each
change on a finding once, as `dmarc-monitor.finding.v1`, with a pointer at
the evidence and never the evidence: [`WEBHOOKS.md`](WEBHOOKS.md),
[`CONNECTWISE.md`](CONNECTWISE.md). One ticket per finding, keyed by the
finding's id; the ticket's number is written back on the finding's history.

---

## What the tests pin

Each of these is a test in `src/DmarcMonitor.Core.Tests/Findings`, and
changing the behaviour means changing the test:

- the same condition observed twice is one finding with one observed event,
  and a different kind of wrong at the same type and severity is recorded on
  it rather than updated silently;
- a failed observation marks findings unknown and resolves nothing;
- a successful observation without the condition resolves after the type's
  threshold, and a sighting in between restarts the count;
- a condition that comes back reopens the same finding;
- closing as an analyst never resolves the source;
- an exception hides the finding from the queue while observation continues,
  and an expired one resurfaces a finding its source still sees;
- an exception needs a review date in the future, an approver and a
  compensating control;
- one organization cannot see or touch another's findings;
- the contract carries a pointer at the evidence and never the evidence;
- source health never shows silence as healthy;
- applying a change resolves nothing; the read that serves the value verifies
  it and resolves the drift together; a receiver's report is the evidence a
  policy is in force; fourteen days without one is verified by DNS only;
- reports stop only while the collector was listening, and never for an
  organization whose mailbox as a whole went quiet; a collector run with
  errors, or an import with a failed file, is recorded as a failed collection
  the source does not trust;
- a destination hears about each change once, and a PSA files one ticket per
  finding however many nights see it.
