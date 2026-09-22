# Code signing

The Windows downloads are not signed. Every person who runs one gets

> **Windows protected your PC**
> Microsoft Defender SmartScreen prevented an unrecognised app from starting.

and has to click *More info* → *Run anyway* to get past it. That dialog is
the single largest difference between this and software somebody bought, and
it costs more than it looks: the way past it is exactly the instruction a
person would be given by something malicious, so teaching customers to click
through it is teaching them a bad habit.

Nothing in the release pipeline needs to change to fix this except the
certificate. `release.yml` already signs and verifies both executables when
the repository secrets below exist, and prints a notice saying the build is
unsigned when they do not.

## What to set

| secret | what it is |
|---|---|
| `SIGNING_ENDPOINT` | the regional endpoint, e.g. `https://eus.codesigning.azure.net` — **this is the switch**: signing runs when it is set and is skipped entirely when it is not |
| `SIGNING_ACCOUNT` | the signing account name |
| `SIGNING_PROFILE` | the certificate profile name |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | a service principal with **Trusted Signing Certificate Profile Signer** on the account |

Set those six and the next tag produces signed binaries. The job then checks
the signature with `Get-AuthenticodeSignature` and fails the release if it is
anything other than `Valid`, or if it carries no timestamp — an untimestamped
signature stops being trusted the day the certificate expires, including on
copies already downloaded.

## Which certificate to buy

Four options, cheapest first. Prices are as of September 2026 and worth
re-checking.

### Azure Artifact Signing — $9.99/month

Formerly Trusted Signing, renamed in 2026. The Basic tier covers 5,000
signatures a month, which is about 4,998 more than a release needs. No
hardware token, no key to store, and the workflow support already written
here targets it.

The catch is eligibility: verified businesses and self-employed individuals
in the US, Canada, EU and UK. It originally required the organisation to have
existed for three years, which excluded most people who would want it;
Microsoft has said it intends to extend validation to younger organisations,
and individual developers can now sign up in public preview. Check current
eligibility before planning around it.

Reputation is not instant — SmartScreen still learns — but signed downloads
accumulate reputation across everything signed by the same identity, rather
than each file starting from nothing.

### SignPath Foundation — free, for open source

SignPath gives OSS projects free OV certificates and a signing service. The
conditions are real ones rather than paperwork:

- an OSI-approved licence with no commercial dual-licensing,
- no proprietary components,
- actively maintained, already released, and documented,
- a public repository with 2FA on the account,
- a written code-signing policy saying which repository is official, what
  gets signed, that only the release workflow signs, and who approves a
  release.

That last point is the one to look at before applying: it is a description of
how releases already work here, so writing it down is mostly transcription.
This route costs nothing and is the obvious first choice **if this repository
is staying open source**. It is not available for a private or commercial
product.

### An OV certificate from a commercial CA — roughly $200–400/year

Sectigo, DigiCert and the rest. Since the CA/Browser Forum tightened storage
rules in June 2023, the private key has to live on a hardware token or in a
cloud HSM, which means either a USB key that has to be plugged into whatever
signs the build — awkward for a hosted runner — or an HSM that costs more
than the certificate.

No advantage over Azure at four times the price, unless a customer's
procurement demands a named CA.

### An EV certificate — roughly $400–700/year

The only option that clears SmartScreen **immediately**, with no reputation
period. Same hardware requirement as OV, plus a heavier identity check.

Worth it if the download page is how customers meet the product and a warning
on day one is unacceptable. Not worth it otherwise.

## The case that needs no certificate at all

If the Windows copy only ever runs on machines inside one organisation —
which is the normal case for an MSP running this internally — a self-signed
certificate distributed to Trusted Publishers by group policy silences
SmartScreen on exactly those machines and costs nothing.

It does nothing for anybody outside that domain, so it is a way to stop
warning your own staff, not a way to ship.

## Until then

The release publishes `SHA256SUMS.txt`, so anybody cautious can check the
file they downloaded is the file the build produced:

```powershell
Get-FileHash .\DMARC-Monitor-Windows.zip
```

That answers "is this what was built" but not "who built it", which is the
question only a signature answers. It is a stopgap, not a substitute.
