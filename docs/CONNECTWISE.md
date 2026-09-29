# ConnectWise PSA

What the nightly DNS scan finds, filed as tickets in ConnectWise PSA
(Manage): one ticket per finding, on the client's own company, with a note
when the finding repeats while a tech still has the ticket open.

The same channel as the [webhook](WEBHOOKS.md): the same events, sent after
the same scan by the same `dmarc-notify.service`, recorded in the same ledger
of what went where, with the credential in the same secret store. An
organization may have one of each, so a Teams channel and the ticket queue can
both hear about a change. The anomaly alerts planned in
[`OPEN-ISSUES.md`](OPEN-ISSUES.md) (12a) will flow through it the same way.

---

## Before you start

Four things from ConnectWise, and one decision:

1. **An API member.** *System › Members › API Members*. Give it a role with
   the least this needs: *Service Desk › Service Tickets* add, edit and
   inquire (on the board below), and *Companies › Company Maintenance*
   inquire. Nothing else. It is the account every ticket will be filed by.
2. **Its public and private key.** *API Keys* on that member. The private key
   is shown once; it goes into the secret store below and nowhere else. If it
   is ever pasted into a chat, a ticket or a screenshot, delete the pair and
   generate a new one.
3. **A clientId.** Register the integration at developer.connectwise.com and
   take the GUID it gives you. ConnectWise refuses any request without it,
   whatever the keys say.
4. **Your company id.** The one you sign in to ConnectWise with - the
   organization's, not a client's.
5. **The service board** tickets should land on, by name as it appears in
   ConnectWise. Optionally a status on that board, and the priority names a
   critical finding and a warning should get; left out, the board's defaults
   apply.

---

## Setting it up on a server

As the service account, so that the keys land in the secret store the service
reads:

```sh
sudo -H -u dmarc /usr/local/bin/dmarc notify set --kind connectwise --org <slug> \
    --site https://api-na.myconnectwise.net \
    --company-id <your company id> \
    --client-id <the clientId GUID> \
    --public-key <the API member's public key> \
    --board "Alerts" \
    --status "New" \
    --priority-critical "Priority 1 - Emergency" \
    --priority-warning "Priority 3 - Medium" \
    --min-severity warning \
    --link-base https://dmarc.example.com \
    --db /opt/dmarc/data/dmarc.db --secrets /opt/dmarc/data/secrets
```

It asks for the private key at a prompt that does not echo. The key never goes
on the command line - shell history, `ps`, the screenshot on the ticket. For a
script, `--secret-stdin` reads it from standard input, or
`DMARC_CONNECTWISE_PRIVATE_KEY` from the environment.

`--site` is the API host: `api-na.myconnectwise.net` for the North American
cloud, `api-eu` and `api-au` for the others, or your own host on premises.
The version path (`/v4_6_release/apis/3.0`) is added when it is left off.

`--link-base` is the address people open the web app on; each ticket carries a
link to the domain's page there. Leave it out and tickets carry no link.

Setting it again replaces the keys and the board and keeps the record of what
was already filed, so a rotated key is one command.

### Which company each client is

A ticket is filed on the client's own ConnectWise company, and the mapping is
made by a person - never guessed from a name, because a slug that happens to
resemble a company identifier would file one customer's ticket on another
customer's account. Find the id, then set it:

```sh
sudo -H -u dmarc /usr/local/bin/dmarc notify companies --org <slug> --search "Acme" \
    --db /opt/dmarc/data/dmarc.db --secrets /opt/dmarc/data/secrets

sudo -H -u dmarc /usr/local/bin/dmarc client set-connectwise --client acme-corp --company 1001 \
    --db /opt/dmarc/data/dmarc.db
```

A client with no company set is not an error: its findings wait, the nightly
run names it, and they are filed once it is mapped (within the same fourteen
days everything else waits). One unmapped client never holds up another's
tickets.

### Prove it

```sh
# signs in, and looks for the board
sudo -H -u dmarc /usr/local/bin/dmarc notify test --org <slug> --kind connectwise \
    --db /opt/dmarc/data/dmarc.db --secrets /opt/dmarc/data/secrets

# and files one test ticket on that client's company; close it there
sudo -H -u dmarc /usr/local/bin/dmarc notify test --org <slug> --kind connectwise --client acme-corp \
    --db /opt/dmarc/data/dmarc.db --secrets /opt/dmarc/data/secrets
```

There is no public ConnectWise sandbox for the product's tests to run against,
so this is the acceptance test, and it is meant to be run on the real instance
on the day. The product's own tests run the same code against a fake
ConnectWise that checks the credential the way the real one does.

The rest is as for the webhook: `dmarc notify list` shows it and whether it is
failing, `sudo systemctl start dmarc-notify` sends what is waiting now, and
`dmarc notify remove --org <slug> --kind connectwise` stops it and forgets the
keys. `dmarc health` reports a destination that has stopped delivering, and
`dmarc-notify.service` fails its unit - and so `dmarc-alert@` - the morning a
run cannot file.

---

## What a ticket looks like

| | |
|---|---|
| summary | `DMARC: Acme Corp: DMARC: p=quarantine → p=none. [dm:3f0c2a52]` - the client, what changed, and a marker (below). Cut to ConnectWise's 100 characters, marker kept |
| board, status | as configured |
| priority | the name configured for the finding's severity; the board's default when none is |
| company | the client's, from `dmarc client set-connectwise` |
| description | the client and domain, the severity, what changed, the record before and after, whether this product itself made the change (a fix applied from the dashboard), when it was seen, the dashboard link, and the event id |

**One ticket per finding.** A finding is one record of one domain: the DMARC
record of `acme.example`, say. A second change to it while a tech has the
ticket open is added as a note on that ticket, not a second ticket. Once the
ticket is closed, the next change opens a new one whose first line names the
old, so the history is one click away.

**One way.** The PSA is the system of record for the work, so this product
never closes, reassigns or reprioritizes a ticket. What a tech does with it
is theirs.

**The marker.** `[dm:` and eight hex characters of the event's id `]`, in the
summary. If ConnectWise created the ticket and the answer never came back -
a dropped connection at the wrong moment - the next run searches for the
marker and finds the ticket rather than filing it again.

### When ConnectWise is down

A run stops at the first failure, so tickets are filed in the order things
happened or not at all, and the next run tries the stuck one first. A rate
limit (429) is treated the same way. A run files a few dozen tickets at most,
well under any published throttle.

A 401 names the credential - one of the four parts is wrong, or the keys were
regenerated. A 403 names the API member's role. Both are in the run's output,
in `dmarc notify list`, and in `dmarc health`.

---

## What is stored where

| | |
|---|---|
| secret store | the API base address, your company id, the public key, the private key and the clientId, under one credential reference |
| the organization's database | the API host for display, the board, status and priority names, the ledger of which event became which ticket number, and each client's company id (`client_settings`) |
| ConnectWise | the ticket: client name, domain, the record before and after, counts, and the dashboard link |

Never a report, never a header, never anybody's mail. The destination is your
own PSA, which already holds the client's records; `DATA-HANDLING.md` lists it
among the product's outbound connections.

A copied database or a backup carries none of the four credential parts. A
run given a different `--secrets` from the one that set the destination finds
no keys and says so rather than trying without them.

### One Windows desktop

The same as for the webhook: the keys are kept with DPAPI for the Windows
account that set them, so set and send as the same account, and the nightly
task runs as you. `WEBHOOKS.md` has the task.
