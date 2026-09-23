# What this has, against what DMARC platforms generally have

A checklist of the common feature set across commercial DMARC products —
dmarcian, EasyDMARC, Red Sift OnDMARC, PowerDMARC, Valimail, URIports — and
where this sits against it.

This is a read of the category, not a vendor-by-vendor survey, and the vendors
move. The value is in the second and third tables: what is genuinely here, and
what is genuinely not.

Every "have it" below was checked against the code rather than remembered.

---

## Have it

| | where |
|---|---|
| Aggregate (RUA) ingestion | Graph mailbox, folder or zip import, browser drag-drop |
| TLS-RPT ingestion | parsed and stored |
| Malformed-report tolerance | one bad message never stops a backlog |
| Deduplication | scoped per domain **and** reporter — report ids are not globally unique, and an unscoped key silently discards the second receiver's whole view |
| Multi-tenant | organizations → clients → domains |
| Compliance, trended | daily series that tell a quiet day from an unreported one |
| Per-source breakdown | clean / misconfigured / signing-unaligned / unauthenticated |
| Sender identification | `SenderCatalog`, from the providers' own published SPF ranges |
| Forwarder vs forgery | `FailureClassifier` — see below |
| Cross-customer correlation | `dmarc intel`; exports indicators for a firewall or SIEM |
| SPF/DKIM/DMARC validation | `dmarc check` |
| SPF lookup-limit counting | resolves the include tree rather than counting terms |
| MTA-STS and TLS-RPT | including **serving** the policy file, and fetching the live one to judge it |
| DNS writes | Cloudflare, Azure DNS, Manual — with dry run, verify, rollback and history |
| Policy rollout guidance | plus `dmarc simulate`, which replays real reports |
| Monthly client report | a PDF drawn server-side, with a long HTML version for reading on screen |
| White-label | colour, logo, name and contact per organization, on both |
| Role-based access | Entra groups; viewer / operator / admin; customer-only logins |
| Audit trail | every write, every DNS change, every prune |
| Retention controls | per data class, forensic shortest |
| Self-hosted | single binary CLI plus a Blazor app on SQLite. No SaaS, no egress of customer data |

## Goes further than the category

| | why it is unusual |
|---|---|
| **Zone-file audit** (`dmarc audit`) | DNS cannot enumerate DKIM selectors — there is no query for it and no wildcard to walk — so a checker can only test the selectors reports have already named, which is every selector that works and none that do not. A zone export names all of them. |
| **Forwarder vs forgery** | Half of every failure on the estate this was built against was one security gateway rewriting the customers' own mail, which nothing in DNS can fix. Most tools render that in the same red number as forgery, so the domain reads as broken and the operator weakens a record trying to fix it. |
| **Policy simulator** | Several tools offer one. This one refuses to answer where the stored row cannot support the answer, and says how many rows it set aside. |
| **Reachability** (`dmarc reachability`) | The RFC 7489 §7.1 authorization record is checked almost nowhere, and its failure mode is total silence: the receiver declines to send and tells nobody. |
| **Evidence discipline** | Throughout: a failed lookup is never reported as an absent record, silence is never turned into an instruction to delete, and anything the data cannot establish is left unsaid. Most of the test suite is about what the product refuses to claim. |

## Do not have it

| gap | state | worth it? |
|---|---|---|
| **Alerting** — email, Slack, webhook | nothing | **Yes, and first.** Real findings with no way to learn about them except by opening the app. For an MSP that is the difference between a product and a report. |
| **Emailed client reports** | `dmarc report` writes the PDF, branded by the organization; nothing sends it | **Yes.** It is the monthly deliverable, and attaching it by hand is the last manual step in it. |
| **RUF / forensic ingestion** | parsed, stored and shown on its own page | Headers only - the body is dropped at the parser. Kept 30 days, subjects and headers gated at the Tech role, and every reveal is audit-logged. Volume stays low whatever you publish: Google, Microsoft and Yahoo do not send failure reports at all. |
| **Public API** | none | Only when something needs to integrate. |
| **SPF flattening** | a `spf_flatten_state` table name and some comments — **no implementation** | Situational. Flattening trades a lookup-limit problem for a staleness problem: the addresses change and the record does not. |
| **Hosted / delegated SPF and DMARC** (CNAME) | no | This is the feature that locks customers into a vendor. Deliberate to skip. |
| **BIMI** | two schema columns, no code | Only once a client asks and has a VMC. |
| **Geolocation of sources** | no | Arguably right to skip. A country flag beside an IP is decoration; the cross-client count is the signal that means something. |
| **SSO beyond Entra** | Entra only — no Google, Okta or SAML | Only if somebody needs it. |

---

## The short version

It is stronger than the category on **DNS-side auditing** and on **not lying
about what it knows**, and weaker on **telling anybody what it found**.

Everything in the first two tables is checkable: `dmarc help` lists it,
[`RUNNING.md`](RUNNING.md) shows it being used, and the commit history says why
each piece is shaped the way it is.
