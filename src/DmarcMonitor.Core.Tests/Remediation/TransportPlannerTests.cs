using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Remediation;

namespace DmarcMonitor.Core.Tests.Remediation;

/// <summary>
/// Publishing MTA-STS and TLS-RPT.
///
/// TLS-RPT is safe: it asks for reports and changes nothing about delivery.
/// MTA-STS in enforce mode is the most dangerous change this product can make
/// - a sender that reaches a mail server the policy does not list does not
/// deliver and does not fall back - and it is dangerous for longer than any
/// other, because senders cache the policy for its max_age whatever is
/// published afterwards. Most of these are about what that refuses.
/// </summary>
public sealed class TransportPlannerTests
{
    private static readonly string[] Microsoft365 = ["acme-com.mail.protection.outlook.com"];

    private static ServedPolicy Serving(string mode, params string[] mx) =>
        new(true, new MtaStsPolicy { Mode = mode, Mx = mx, Id = "20260918120000" }, null);

    // ---- TLS-RPT -------------------------------------------------------------

    [Fact]
    public void PublishesTlsReportingWhereThereIsNone()
    {
        var plan = TransportPlanner.TlsReporting("acme.com", null, "tls@nrgtechservices.com");

        Assert.True(plan.IsSafe);
        Assert.False(plan.IsNoop);
        Assert.Equal("_smtp._tls.acme.com", plan.RecordName);
        Assert.Equal("v=TLSRPTv1; rua=mailto:tls@nrgtechservices.com", plan.ProposedValue);
    }

    [Fact]
    public void SaysWhoStopsGettingTlsReports()
    {
        // Repointing them here is usually the intent, and somebody else is
        // currently receiving them and will not be told.
        var plan = TransportPlanner.TlsReporting(
            "acme.com", "v=TLSRPTv1; rua=mailto:postmaster@acme.com", "tls@nrgtechservices.com");

        Assert.True(plan.IsSafe);
        Assert.Contains(plan.Warnings, w => w.Contains("postmaster@acme.com", StringComparison.Ordinal));
    }

    [Fact]
    public void AlreadyReportingHereIsANoop()
    {
        var plan = TransportPlanner.TlsReporting(
            "acme.com", "v=TLSRPTv1; rua=mailto:tls@nrgtechservices.com", "tls@nrgtechservices.com");

        Assert.True(plan.IsNoop);
    }

    [Fact]
    public void RefusesToOverwriteSomethingThatIsNotTlsRpt()
    {
        var plan = TransportPlanner.TlsReporting("acme.com", "some-other-verification=abc", "tls@example.com");

        Assert.False(plan.IsSafe);
    }

    [Fact]
    public void RefusesAReportingAddressThatIsNotOne()
    {
        var plan = TransportPlanner.TlsReporting("acme.com", null, "tls.nrgtechservices.com");

        Assert.False(plan.IsSafe);
    }

    // ---- MTA-STS: the file comes first ---------------------------------------

    [Fact]
    public void RefusesToAnnounceAPolicyNobodyIsServing()
    {
        // The whole failure mode of MTA-STS in one test. The TXT record is the
        // easy half and the half this product can publish; publishing it alone
        // announces a promise nothing can keep.
        var plan = TransportPlanner.MtaSts(
            "acme.com", null, ServedPolicy.Missing("there is no file there"), Microsoft365);

        Assert.False(plan.IsSafe);
        Assert.Contains("Serve the policy first", plan.Blockers[0], StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesWhenTheFileIsThereButIsNotAPolicy()
    {
        var plan = TransportPlanner.MtaSts(
            "acme.com", null, new ServedPolicy(true, null, "the file does not parse"), Microsoft365);

        Assert.False(plan.IsSafe);
    }

    [Fact]
    public void AnnouncesAPolicyThatIsBeingServed()
    {
        var plan = TransportPlanner.MtaSts(
            "acme.com", null, Serving(MtaStsMode.Testing, "*.mail.protection.outlook.com"), Microsoft365);

        Assert.True(plan.IsSafe);
        Assert.Equal("_mta-sts.acme.com", plan.RecordName);
        Assert.Equal("v=STSv1; id=20260918120000", plan.ProposedValue);
    }

    [Fact]
    public void RefusesToAnnounceAPolicyWhoseIdIsMissing()
    {
        // The id exists only in the TXT record - RFC 8461 policy files do not
        // carry it - so a policy built by fetching the file alone has none,
        // and ToRecord() produced the literal "v=STSv1; id=". Every sender
        // treats an unparseable record as no MTA-STS policy at all, so
        // applying it would have switched transport security off for the
        // domain while the page reported success.
        //
        // Both call sites did exactly that, and no test caught it because
        // every fixture here supplies an id. This is the fixture that does not.
        var noId = new ServedPolicy(
            true,
            new MtaStsPolicy { Mode = MtaStsMode.Testing, Mx = ["*.mail.protection.outlook.com"], Id = "" },
            null);

        var plan = TransportPlanner.MtaSts("acme.com", null, noId, Microsoft365);

        Assert.False(plan.IsSafe);
        Assert.Contains(plan.Blockers, b => b.Contains("policy id", StringComparison.Ordinal));
        Assert.DoesNotContain("id=\"\"", plan.ProposedValue, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("has-a-hyphen")]
    [InlineData("far too long to be a valid mta sts policy identifier")]
    public void KnowsWhichIdsASenderWillAccept(string id) =>
        Assert.False(MtaStsPolicy.IsValidId(id));

    [Fact]
    public void SaysTestingEnforcesNothing()
    {
        var plan = TransportPlanner.MtaSts(
            "acme.com", null, Serving(MtaStsMode.Testing, "*.mail.protection.outlook.com"), Microsoft365);

        Assert.Contains(plan.Warnings, w => w.Contains("delivers anyway", StringComparison.Ordinal));
    }

    // ---- MTA-STS: enforce is the dangerous one --------------------------------

    [Fact]
    public void RefusesToAnnounceAnEnforcingPolicyThatMissesAMailServer()
    {
        // Every message to that server stops being delivered. Not degraded:
        // refused, and for as long as senders keep the cached policy.
        var plan = TransportPlanner.MtaSts(
            "acme.com", null, Serving(MtaStsMode.Enforce, "mail.acme.com"), Microsoft365);

        Assert.False(plan.IsSafe);
        Assert.Contains("refuse to deliver", plan.Blockers[0], StringComparison.Ordinal);
        Assert.Contains("acme-com.mail.protection.outlook.com", plan.Blockers[0], StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesToAnnounceAnEnforcingPolicyItCannotCheck()
    {
        // No MX means no way to know whether the policy lists the right hosts.
        // Unknown is not the same as fine.
        var plan = TransportPlanner.MtaSts(
            "acme.com", null, Serving(MtaStsMode.Enforce, "mail.acme.com"), []);

        Assert.False(plan.IsSafe);
        Assert.Contains("could not be read", plan.Blockers[0], StringComparison.Ordinal);
    }

    [Fact]
    public void AnnouncesAnEnforcingPolicyThatCoversEverything()
    {
        var plan = TransportPlanner.MtaSts(
            "acme.com", null, Serving(MtaStsMode.Enforce, "*.mail.protection.outlook.com"), Microsoft365);

        Assert.True(plan.IsSafe);
    }

    [Fact]
    public void WarnsInTestingAboutWhatWouldBreakOnEnforcing()
    {
        // Harmless today and the exact thing that breaks the day somebody
        // flips the mode. Said now, while it costs nothing to fix.
        var plan = TransportPlanner.MtaSts(
            "acme.com", null, Serving(MtaStsMode.Testing, "mail.acme.com"), Microsoft365);

        Assert.True(plan.IsSafe);
        Assert.Contains(plan.Warnings, w => w.Contains("would stop", StringComparison.Ordinal));
    }

    [Fact]
    public void UpdatingTheIdIsHowSendersAreToldToFetchAgain()
    {
        var plan = TransportPlanner.MtaSts(
            "acme.com", "v=STSv1; id=20200101000000",
            Serving(MtaStsMode.Testing, "*.mail.protection.outlook.com"), Microsoft365);

        Assert.True(plan.IsSafe);
        Assert.Equal("v=STSv1; id=20260918120000", plan.ProposedValue);
        Assert.Contains("fetch the policy again", plan.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void AnnouncingWhatIsAlreadyAnnouncedIsANoop()
    {
        var plan = TransportPlanner.MtaSts(
            "acme.com", "v=STSv1; id=20260918120000",
            Serving(MtaStsMode.Testing, "*.mail.protection.outlook.com"), Microsoft365);

        Assert.True(plan.IsNoop);
    }

    [Fact]
    public void RefusesToOverwriteSomethingThatIsNotMtaSts()
    {
        var plan = TransportPlanner.MtaSts(
            "acme.com", "v=spf1 -all", Serving(MtaStsMode.Testing, "*.mail.protection.outlook.com"), Microsoft365);

        Assert.False(plan.IsSafe);
    }

    // ---- moving to enforce ----------------------------------------------------

    [Fact]
    public void WillNotEnforceWithoutEvidenceThatSendersCanConnect()
    {
        // The transport-security version of advancing p=none, and it wants
        // the same thing first: reports.
        var blockers = TransportPlanner.WhatBlocksEnforcing(
            Serving(MtaStsMode.Testing, "*.mail.protection.outlook.com"),
            Microsoft365, tlsReportsArriving: false, failedSessions: 0);

        Assert.Contains(blockers, b => b.Contains("No TLS reports", StringComparison.Ordinal));
    }

    [Fact]
    public void WillNotEnforceWhileConnectionsAreFailing()
    {
        var blockers = TransportPlanner.WhatBlocksEnforcing(
            Serving(MtaStsMode.Testing, "*.mail.protection.outlook.com"),
            Microsoft365, tlsReportsArriving: true, failedSessions: 12);

        Assert.Contains(blockers, b => b.Contains("undelivered mail", StringComparison.Ordinal));
    }

    [Fact]
    public void NothingBlocksEnforcingOnACleanFortnight()
    {
        var blockers = TransportPlanner.WhatBlocksEnforcing(
            Serving(MtaStsMode.Testing, "*.mail.protection.outlook.com"),
            Microsoft365, tlsReportsArriving: true, failedSessions: 0);

        Assert.Empty(blockers);
    }

    [Fact]
    public void AlreadyEnforcingHasNothingLeftToBlock()
    {
        var blockers = TransportPlanner.WhatBlocksEnforcing(
            Serving(MtaStsMode.Enforce, "*.mail.protection.outlook.com"),
            Microsoft365, tlsReportsArriving: false, failedSessions: 0);

        Assert.Empty(blockers);
    }
}
