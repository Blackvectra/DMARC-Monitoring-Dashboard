# Code signing

The Windows downloads are not signed. Every person who runs one gets

> **Windows protected your PC**
> Microsoft Defender SmartScreen prevented an unrecognised app from starting.

and has to click *More info* → *Run anyway*. That dialog is the largest
single difference between this and software somebody bought, and it costs
more than it looks: the way past it is exactly the instruction a person would
be given by something malicious, so teaching customers to click through it is
teaching them a bad habit.

**Read the next section before buying anything.** The obvious assumption -
that a certificate makes the warning go away - is wrong, and it is the
assumption that gets an EV certificate bought for several hundred pounds a
year to no effect.

## Signing does not remove the warning. It starts a clock.

SmartScreen weighs two things: the reputation of the file's hash, and the
reputation of the publisher's certificate. A brand-new binary signed with a
brand-new certificate has neither. Microsoft's own guidance:

> Even when signed, a newly created binary could still show a SmartScreen
> warning until its hash or publisher certificate accumulates sufficient
> evidence of positive reputation.

and on how long that takes:

> There is no exact threshold, but it can take **several weeks and hundreds of
> clean installs from a wide audience**.

What signing buys is that reputation **accumulates across releases** instead
of resetting. An unsigned build starts from zero every single time; a signed
one inherits what the certificate has earned. That is the whole benefit, and
it is a real one - but it is compounding interest, not a switch.

### EV certificates no longer help

This used to be false, and much of the advice on the internet still is.
Microsoft, in the SmartScreen documentation:

> EV certificates no longer bypass SmartScreen. Years ago, signing files with
> an Extended Validation (EV) code signing certificate would result in
> positive SmartScreen reputation by default, but **this behavior no longer
> exists**. EV certificates may matter for enterprise procurement, but they no
> longer impact SmartScreen behavior. **Paying a premium for EV solely to
> avoid SmartScreen warnings is no longer justified.**

Azure Artifact Signing does not issue EV certificates at all, and Microsoft
says there is no plan to. Buy EV only if a customer's procurement demands the
letters.

### The only two things that remove the warning outright

1. **The Microsoft Store.** Store apps are re-signed by Microsoft and are
   never subject to a SmartScreen download warning. Not a fit for this - it is
   a server product with a trial copy attached - but it is the honest answer
   to "how do I make it stop".
2. **Being inside the organisation.** See *The case that needs no
   certificate* below. For an MSP this is the one that actually matters.

## Nothing here is instant

| route | before you can sign | then |
|---|---|---|
| Azure Artifact Signing | identity validation, **1-7 business days** officially, and reports of 12 days to 3 weeks are common. Cannot be expedited | reputation builds over weeks |
| SignPath Foundation | **not available - see below.** The licence rules it out | — |
| Commercial OV | validation, plus getting a hardware token or HSM working in CI | same |

Two Azure prerequisites that are easy to miss and will stop you on day one:

- **A paid subscription is required.** Free, trial and sponsored Azure
  subscriptions are explicitly unsupported; the portal refuses to create the
  account.
- Eligibility is verified businesses and self-employed individuals in the US,
  Canada, EU and UK. Organisations under three years old were originally
  excluded; individual validation is now open and is a separate path with its
  own document checks.

## What to set

`release.yml` already signs and verifies both executables when these exist,
and prints a notice saying the build is unsigned when they do not.

| secret | what it is |
|---|---|
| `SIGNING_ENDPOINT` | the regional endpoint, e.g. `https://eus.codesigning.azure.net` — **this is the switch**: signing runs when it is set, and is skipped entirely when it is not |
| `SIGNING_ACCOUNT` | the signing account name |
| `SIGNING_PROFILE` | the certificate profile name |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | a service principal with **Certificate Profile Signer** on the account |

Set those six and the next tag produces signed binaries. The job then checks
the signature with `Get-AuthenticodeSignature` and fails the release if it is
anything other than `Valid`, or if it carries no timestamp — an untimestamped
signature stops being trusted the day the certificate expires, including on
copies already downloaded.

## Which to choose

### SignPath Foundation is not available to this project

It is the obvious first thing to reach for - free OV certificates and a
signing service for open source - and it is ruled out by `LICENSE`. Their
conditions require

> an OSI-approved Open Source license

with

> no commercial dual-licensing for all components

and no

> proprietary, non open-source component.

`LICENSE` here opens with `PROPRIETARY SOFTWARE LICENSE`, its second clause
is headed **NO LICENSE GRANTED**, and its third offers paid licences for
commercial use, managed-service deployment and white-label redistribution.
That is three failures out of three, and the third is the exact arrangement
the word "dual-licensing" excludes.

A public repository is not an open source one. The source is readable on
GitHub because the platform's terms let signed-in users read public
repositories - which `LICENSE` says in as many words - and that grants
nobody any right to use it. Applying anyway would mean representing this as
something it is not, to an organisation whose whole purpose is vouching for
identity.

This changes only if the licence changes, and that is a business decision
about clause 3, not a signing decision.

### Azure Artifact Signing, $9.99/month

So: this one. The Basic tier covers 5,000 signatures a month, about 4,998
more than a release needs. No hardware token, no key to hold, and it is what
the workflow here already targets - six secrets and the next tag is signed.

It has no objection to proprietary software. What it validates is who you
are, not how you licence.

### SignPath's paid tiers

SignPath also sells commercial subscriptions, which a proprietary project can
use. Worth a look only if their release-approval workflow is wanted for its
own sake; for signing alone it is more than Azure costs.

**Commercial OV, roughly $200-400/year**, is worth it only if a customer
demands a named CA. Since the CA/Browser Forum tightened key storage in June
2023 the private key must live on a hardware token or in an HSM, which means
either a USB key plugged into whatever runs the build - awkward for a hosted
runner - or an HSM that costs more than the certificate.

## The case that needs no certificate at all

If the Windows copy only ever runs on machines inside one organisation -
the normal case for an MSP running this internally, and probably the case
that matters most here - then:

- a self-signed certificate pushed to **Trusted Publishers** by group policy
  silences the warning on exactly those machines, for nothing; and
- an enterprise administrator can **submit the signed file to the [Microsoft
  Security Intelligence portal](https://www.microsoft.com/en-us/wdsi/filesubmission)**,
  which Microsoft says "can accelerate trust for internal or managed
  deployments" - the one supported way to short-circuit the reputation wait,
  and it is aimed squarely at managed estates.

Neither does anything for a stranger downloading from GitHub. They are a way
to stop warning your own staff and your own customers' machines, not a way to
ship to the public.

## One more thing that is coming

On Windows 11, **Smart App Control** can supersede SmartScreen entirely and
will block unsigned files outright, with no *Run anyway* - and it checks every
executable, not only downloaded ones. It is off by default on upgraded
machines and on for some clean installs. That moves signing from "removes a
warning eventually" towards "runs at all", which is the real argument for
doing it.

## Until then

The release publishes `SHA256SUMS.txt`, so anybody cautious can check the
file they downloaded is the file the build produced:

```powershell
Get-FileHash .\DMARC-Monitor-Windows.zip
```

That answers "is this what was built" but not "who built it", which is the
question only a signature answers. A stopgap, not a substitute.

## Sources

- [SmartScreen reputation for Windows app developers](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)
- [Artifact Signing FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq)
- [Artifact Signing pricing](https://azure.microsoft.com/en-us/pricing/details/artifact-signing/)
- [SignPath Foundation conditions](https://signpath.org/terms.html)
