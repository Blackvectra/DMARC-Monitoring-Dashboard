# Why not just run parsedmarc and OpenSearch?

The honest answer: **they are not the same category**, and for a while you may
want both.

[parsedmarc](https://github.com/domainaware/parsedmarc) + OpenSearch is a *log
pipeline and analytics stack*. It parses reports into documents and hands you a
search index with dashboards. It is Apache 2.0, mature, and has years of field
use behind it.

This is a *decision and remediation tool*. It parses the same three report
types, but its output is a ranked worklist, a DNS change it can apply and
verify, and a document you hand a customer.

> parsedmarc answers **"what does the data say?"**
> This answers **"which of my forty client domains is broken, why, and what do
> I change in DNS tonight?"**

---

## Side by side

| | parsedmarc + OpenSearch | This |
|---|---|---|
| Parses rua / ruf / TLS-RPT | yes (RFC 7489 / 6591 / 8460) | rua and TLS-RPT; **ruf not parsed** |
| Storage | OpenSearch/Elasticsearch cluster (JVM), or Splunk, Kafka, S3 | one SQLite file |
| Presentation | Dashboards or Grafana — you build or import the visualisations | fixed opinionated screens |
| Ad-hoc querying | **yes — full DSL, arbitrary slicing** | not in the product; `dmarc export` hands the rows to jq, a spreadsheet or an index |
| Retention | ILM: rollover, hot/warm, delete | `dmarc prune`, weekly, per data class, audited |
| DNS awareness | **none** — it never looks at your zone | live SPF/DKIM/DMARC/MTA-STS/TLS-RPT, RFC 7208 lookup counting, zone-file audit |
| Remediation | none | plan → apply with a reason → verify → revert, via Cloudflare, Azure DNS or copy-paste |
| Policy simulation | none | replay stored reports against an unpublished record |
| Multi-tenant | one index set, one Dashboards instance | organizations → clients → domains, Entra groups, customer logins, white-label |
| Client deliverable | a dashboard screenshot | a rendered narrative report for a non-technical reader |
| Deployment | JVM cluster + Python + a mail fetcher, usually Docker Compose | two self-contained artifacts, one bootstrap script, no runtime install |
| Ingest | **IMAP, Gmail API, Graph, maildir, S3, Kafka** | Microsoft Graph, folder, zip, browser upload |
| Enrichment | **GeoIP, reverse DNS** | neither, deliberately |
| Alerting | **the OpenSearch alerting plugin** | none |
| Licence | Apache 2.0 | proprietary |

---

## What this does that an index structurally cannot

These are not features parsedmarc forgot. They are outside its job, and they
share one property: **they are about what the data does not contain.** An index
is excellent at what is in it.

**Ranking, never averaging.** `TriageService` orders domains worst-first. A
dashboard tile reading "94% across the book" hides the one domain at 40%. That
is the specific failure of BI-on-DMARC for an MSP: the number goes up and to
the right while a customer is losing mail.

**Closing the loop into DNS.** An index can tell you source X fails DKIM. It
does not know your SPF is at eleven lookups, does not know the selector was
never published, and cannot write the record. `ZoneAudit` cross-references
three sources of truth — the zone file you believe is live, what DNS actually
serves, and what receivers reported seeing — and says which one each finding
came from.

**Reports that never arrived.** RFC 7489 §7.1: when a client's `rua` points at
your domain, your domain must publish an authorization record. A receiver that
looks, finds nothing, and declines to send **produces no documents at all**. In
an index that is indistinguishable from a quiet customer. Three of sixteen real
domains were broken this way and every one was found by hand before
`dmarc reachability` existed.

**What a change would cost, before making it.** `dmarc simulate` replays stored
reports against a record nobody has published. That is counterfactual
evaluation under the RFC's rules — alignment counting only where the mechanism
actually authenticated — not aggregation. A query tells you what happened; it
cannot tell you what would happen.

**Mail your own tooling broke, apart from forgery.** On the estate this was
built against, half of every failure was one hosted security gateway rewriting
the customers' own mail — and nothing published in DNS can fix that. In an
index, that and a forgery are both `dmarc=fail` rows. Read as a configuration
fault, it sends an operator to weaken a record that was never the problem.

**A receiver that went quiet.** A reporter that used to carry a domain's mail
and stopped is an *absence* of documents — invisible unless somebody thought to
query for the gap. It is also the dangerous shape, because reports keep
arriving and the pass rate quietly becomes "whoever is left".

**Verified-but-unaligned DKIM.** `dkim=pass` beside `dmarc=fail` reads as a
contradiction in raw XML. It is a valid signature over the wrong domain, and
the fix is at the vendor rather than in the key. Explained here rather than
charted.

**Naming a sender without guessing.** `SenderCatalog` groups by providers'
published ranges, not reverse DNS, because a wrong PTR-derived label —
"Microsoft 365" on an intruder's line — is worse than a bare IP address. One
real domain had 630 "sources" in a month; 618 were Microsoft load balancers.

---

## Where the stack wins

Stated plainly, because a comparison that only flatters the thing writing it is
not worth reading.

**Scale.** SQLite is a single writer. That is fine for a book of small-business
domains and it is not fine for a tenant sending tens of millions of messages a
month with deep retention. OpenSearch shards. Retention here is now enforced
(`dmarc prune`), which moves the ceiling but does not remove it.

**Arbitrary investigation.** "Every address that hit these three domains,
aligned on SPF only, in a six-hour window" is one query in a DSL. Here it is a
`dmarc export` and a jq or a spreadsheet — which answers it, but as a second
step and without a saved visualisation at the end of it. `dmarc intel` covers
cross-client correlation specifically, not the general case.

**Enrichment.** GeoIP and reverse DNS out of the box. This does neither.

**Alerting.** OpenSearch has an alerting plugin. Nothing here pages anybody —
you find out by looking, which for an MSP is the single largest gap.

**Ingest breadth.** IMAP, Gmail, maildir, S3, Kafka. Here it is Microsoft Graph
for unattended collection, plus importing a folder, a zip or a drag-drop for
everything else. A client not on Microsoft 365 forwards or exports; that works,
but it is not unattended.

**Failure reports.** parsedmarc parses RUF. This has the schema and the
retention window and no parser, so the table is empty.

**Maturity and licence.** Years of production use, Apache 2.0, a community.
This is proprietary and young, and `INGEST-SETUP.md` says plainly that the
Graph collection path has never run against a live Exchange mailbox.

---

## Running both

They are complementary more than competing, and the sane pattern is:

- **This** stays the operator- and customer-facing layer. The DNS and
  remediation half has no equivalent in that stack and would stay here whatever
  else changed.
- **OpenSearch** takes raw reports for deep retention and ad-hoc forensics if a
  tenant's volume outgrows one file.

`dmarc export` is the shipper. NDJSON by default because that is what `_bulk`,
jq and Splunk's HEC read, and `--after-id` makes each run incremental — rows are
never rewritten once stored, so everything above the last id shipped is exactly
the new mail:

    dmarc export --after-id 41232 \
      | jq -c '{index:{_index:"dmarc",_id:.id}},.' \
      | curl -s -H 'Content-Type: application/x-ndjson' \
             --data-binary @- https://opensearch.example/_bulk

Taking `_id` from the row makes a re-run idempotent. The export opens the
database read-only, so it runs while the collector has it.

Keep retention here aggressive and let the index hold the long tail. A prune of
1,210 reports on the real database removed 14,924 records: the reports carry
the provenance and the records are the bulk.

---

## Choosing one

**Take parsedmarc and OpenSearch if** you are one organization, you want to
slice the data yourself, you already run Elasticsearch, or you need GeoIP,
alerting and IMAP today.

**Take this if** you manage domains for other people, the output you need is a
worklist and a customer-facing report rather than a dashboard, and you want the
DNS side — finding the fault, planning the record, applying it, verifying it —
in the same tool that found it.
