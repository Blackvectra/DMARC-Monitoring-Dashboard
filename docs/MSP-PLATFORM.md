# The MSP platform brief, against what is actually here

A section-by-section read of the "Email Authentication and DNS Security
Operations platform for MSPs" brief against this codebase, on 22 September
2026.

Every **have** below was checked against the code today, not remembered. Every
**none** means exactly that: no implementation, whatever the schema or the
comments suggest.

The short version: **the data layer and the tenancy model are largely built,
and the operations layer is not.** What exists is a product that knows things.
What the brief describes is a product that tells somebody and tracks what they
did about it. That is the gap, and it is narrower than the brief's length
suggests — most of Phase 1 is wiring, not discovery.

---

## 1. Multi-tenant control plane

| the brief asks for | state | where |
|---|---|---|
| Tenant isolation in the database, UI, exports and jobs | **have** | every query carries `tenant_id`; organization scope resolved once per request in `OrgContext` |
| One MSP login across many clients | **have** | organizations → clients → domains, with an organization picker |
| Role-based access | **have**, four roles not six | `OrganizationRole`: Viewer, Tech, Engineer, Admin, plus customer-only logins restricted to one client |
| MFA | **have**, inherited | Entra does it; there is no local password to protect |
| Audit logs | **have** | every write, DNS change and prune; failure-report reveals too |
| White-label client portal | **have** | colour, logo, name and contact per organization |
| API keys, session controls | **none** | there is no API to key |
| Cross-tenant dashboards that never leak evidence | **have** | `dmarc intel` counts other clients without naming them |

**Gap:** Platform Admin and Auditor as distinct roles; API keys.

## 2. Portfolio dashboard

| | state | where |
|---|---|---|
| All clients and domains in one view | **have** | Dashboard, worst first, with a client filter |
| Health, policy, pass rate, failing volume, last report date | **have** | the triage table |
| Enforcement readiness | **partial** | computed per domain in the report model today; not a column on the portfolio view |
| New sender count, open remediations, DNS drift, alert severity | **none** | none of these are tracked as state |
| Filter by risk, owner, service plan, open findings | **partial** | severity, client and text search; no owner, plan or findings |
| Saved analyst views ("all domains still at p=none") | **none** | filters are not nameable or saveable |

**Gap:** the saved views are the cheapest high-value item in the whole brief —
every one of them is a query the product can already answer.

## 3. Aggregate report intelligence

| | state |
|---|---|
| Parse, retain, deduplicate, validate | **have** — dedup scoped per domain *and* reporter |
| Raw evidence kept for audit | **have** — the original XML is stored |
| Source IP, count, receiver, disposition, SPF/DKIM result, From, envelope, `d=`, selector | **have** — all stored per record |
| SPF/DKIM pass distinguished from *aligned* pass | **have** — and it is the middle bucket of the Per result view |
| DMARC pass computed as aligned SPF OR aligned DKIM | **have** |
| Policy override separated from declared policy | **have** — overrides are their own segment everywhere |
| Trend by domain, sender, source, receiver, period | **have** |
| Trend by ASN and country | **none** — no geo or ASN data is collected |

**Gap:** effectively none, except geo/ASN, which is a deliberate skip: an
IP-to-location database cannot be resolved offline and a map drawn from
nothing is decoration.

## 4. Sender intelligence and classification

| | state |
|---|---|
| Classify approved / misconfigured / unknown / suspicious / retired | **have as a computed view**, **none as stored state** |
| Sender owner, business purpose, vendor, notes | **none** — nowhere to put them |
| First seen, last seen, volume | **partial** — derivable per period, not stored per sender |
| Analyst confirmation before "approved" | **none** |
| Detect new senders, volume spikes, regression, disappearance | **partial** — retirement is detected for the client report; the rest is not |
| Never call a source malicious on a DMARC failure alone | **have**, and it is enforced by tests |

**Gap: this is the single biggest one.** The classification logic exists and is
good; there is no table behind it, so nothing can be confirmed, assigned,
annotated or remembered between reports. Everything in the brief's workflow
language — owner, validation request, exception, review date — needs that table
first.

## 5. DNS posture and drift

| | state |
|---|---|
| Monitor DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT | **have** — nightly, stored as content-addressed snapshots |
| BIMI | **none** — two schema columns, no code |
| DNSSEC / DANE | **none** |
| Historical snapshots with timestamps | **have** — keyed on content hash, so a change is a new row |
| Readable record diffs | **none** — the data supports it, nothing renders it |
| Alert on policy weakened, SPF invalid, selector disappearing, MTA-STS failing | **none** — `dns_drift_events` is a table nothing writes to |
| Plain-English impact on every alert | **partial** — the chips and the Fix page say it; no alert carries it |
| Baseline approval workflow | **none** |

**Gap:** drift detection is the brief's headline differentiator and it is the
clearest hole in the product. The snapshots are already there and already
distinguish "changed" from "unreadable" — a diff and a severity rule would turn
stored history into the feature.

## 6. Enforcement readiness

| | state |
|---|---|
| Per-domain maturity path | **partial** — triage levels approximate it |
| Readiness scored from observed data | **have** — per domain, and it refuses an estate average |
| Configurable observation window | **none** — the window is a fixed choice per view |
| Show unaligned approved traffic and expected impact before a change | **have** — `dmarc simulate` replays real reports and refuses where rows cannot support an answer |
| Staged `pct` recommendations | **partial** — the planner understands `pct`; nothing proposes a staircase |
| Exact proposed TXT records, with approval, audit and rollback | **have** — Cloudflare, Azure DNS and Manual, with dry run, verify and rollback |
| Approved exceptions with expiry | **none** |

## 7. Alerting and case management

| | state |
|---|---|
| Severity levels | **partial** — triage has five levels; alerts have none because alerts do not exist |
| Alert with tenant, domain, sender, evidence, recommended action, owner, SLA | **none** |
| The eleven alert types listed | **none** — one exists as a systemd unit: a collector that has stopped |
| Acknowledge, assign, comment, suppress, escalate, close, reopen | **none** |
| Correlation into incidents | **partial** — `dmarc intel` correlates sources across clients; no incident object |

**Gap: nothing here exists as state.** This and §4 are the two that make the
product a platform rather than a viewer, and they need the same thing first: a
table with a lifecycle in it.

## 8. Reporting and exports

| | state |
|---|---|
| White-label monthly client report | **have** — a PDF, drawn server-side, with this product's own header, footer and page numbers |
| PDF | **have** — `dmarc report` writes one per client, and the app serves it; `--html` still writes the long on-screen version |
| CSV / XLSX | **partial** — `dmarc export` writes CSV and NDJSON of the raw data; no report appendix workbook |
| Executive / technical / QBR split | **none** — one report, currently between executive and technical |
| Logo, colours, client, period, analyst, confidentiality label, report ID | **partial** — first four yes, in both renderings; last three no |
| Scheduled per tenant, immutable history | **none** — generated on demand, not kept |
| Raw and normalized export for audit | **have** |

## 9. Integrations and automation

| | state |
|---|---|
| REST / OpenAPI | **none** |
| Webhooks | **none** |
| PSA, SIEM, SOAR, Teams, Slack, email | **none** — `dmarc intel` exports indicators a SIEM can read, which is the nearest thing |
| Bulk onboarding by CSV or API | **partial** — an import files every domain it finds, and now creates a client per domain; no CSV of tenants |
| Domain and subdomain discovery with review | **partial** — discovery happens on import; review does not |
| RUA endpoint setup, tenant-specific and validated | **have** — `dmarc reachability` checks the RFC 7489 §7.1 authorization almost nobody checks |
| Health checks for queues, polling, storage, notifications, backups | **partial** — `dmarc health` covers backups and collection; nothing covers notifications, because there are none |

## 10. Security and operations

| | state |
|---|---|
| Default-deny authorization, tenant scoping on every query | **have** |
| Audit logging across logins, exports, role changes, DNS proposals | **have** |
| Encryption in transit and at rest | **have** — backups encrypted; SQLite at rest is the host's job, documented |
| Retention by tenant and data class | **have** |
| Backup, restore verification, health dashboard | **have** |
| Rate limiting, input validation, zip-bomb protection, safe parsing | **have** — bounded readers throughout, and the importer survives a bad message |
| Idempotent ingestion, retries, dead letters | **partial** — ingestion is idempotent; there is no queue to retry |
| Documented deployment, upgrade, rollback, DR | **have** |
| No forensic content stored by default | **have** — the body is dropped at the parser |

## 11. UX

| | state |
|---|---|
| What changed / what is risky / who owns it / what next | **two of four** — risk and next action are answered; "what changed" and "who owns it" are not |
| Every red metric links to the evidence | **have** — sources, domains and the Fix page are all reachable from the number |
| Queues, cases, approvals, history | **none** beyond the DNS change history |
| High-risk actions deliberate: preview, approve, audit, rollback | **have** — for DNS writes, which are the high-risk actions |

---

## What Phase 1 actually needs

The brief's Phase 1 is ten items. Seven are done:

1. ~~Strict multi-tenancy and RBAC~~ — done
2. MSP portfolio dashboard — **mostly**; needs the saved views and a findings column
3. ~~Reliable RUA ingestion, dedup, report health~~ — done
4. **Sender inventory with approval workflow** — the classification is done, the table is not
5. ~~DMARC/SPF/DKIM checks with historical snapshots~~ — done
6. **Critical DNS drift alerts** — snapshots exist, diffing and alerting do not
7. ~~Client-facing monthly report~~ — done, as a branded PDF; what is left is
   sending and keeping it, which is item 8's table and a delivery path
8. **Open remediation queue with owners, statuses, due dates** — the register is computed per report; nothing persists it
9. CSV export plus documented API — **CSV done**, API not started
10. ~~Audit logs and backup/restore verification~~ — done

So Phase 1 is four pieces of work, in dependency order:

1. **A findings table with a lifecycle.** Owner, status, severity, evidence,
   opened, closed, reason. Everything else in the brief hangs off it: a sender
   awaiting validation, a drift event, a remediation item and an alert are all
   the same row with a different type.
2. **DNS drift detection** on the snapshots already stored, writing findings.
3. **Sender state** — approve, assign an owner, note a vendor, set an exception
   with a review date — writing and reading findings.
4. **Notification routing**: email and a generic webhook. One delivery path,
   not twelve integrations.

Everything in Phase 2 and Phase 3 is genuinely later, with one exception worth
pulling forward: **record diffs in plain English**, because the snapshots are
already there and it is the demonstration that sells the drift feature.

## What not to rebuild

These read as gaps in the brief and are already here, done carefully:

- alignment vs raw pass, everywhere, including its own report view;
- forwarder against forger, which is half of every failure on a real estate;
- the policy simulator, which refuses to answer where the data cannot;
- reachability checking of the RUA authorization record;
- DNS writes with dry run, verify, rollback and history;
- retention, erasure and the audit trail;
- evidence discipline throughout: a failed lookup is never a missing record.
