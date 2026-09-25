using DmarcMonitor.Core.Dns;
using Xunit;

namespace DmarcMonitor.Core.Tests.Dns;

/// <summary>
/// What changed between two readings, and how much it matters.
///
/// Severity is about consequence. Each case below is a change a client or
/// their registrar makes without telling the MSP, and the test is whether it
/// lands with the weight it deserves.
/// </summary>
public sealed class DnsDriftTests
{
    private static DnsState State(
        string? spf = "v=spf1 include:_spf.google.com include:servers.mcsv.net -all",
        string? dmarc = "v=DMARC1; p=reject; rua=mailto:dmarc@msp.example",
        int spfCount = 1, string? mtaSts = "v=STSv1; id=1", string? tlsRpt = "v=TLSRPTv1; rua=mailto:tls@msp.example") =>
        new() { Spf = spf, SpfCount = spf is null ? 0 : spfCount, Dmarc = dmarc, MtaSts = mtaSts, TlsRpt = tlsRpt };

    [Fact]
    public void NothingChangedIsNoDrift()
    {
        Assert.Empty(DnsDrift.Compare(State(), State()));
    }

    /// <summary>The commonest real one: a platform move drops a sender's include.</summary>
    [Fact]
    public void ARemovedIncludeIsNamedAndWorthAWarning()
    {
        var change = Assert.Single(DnsDrift.Compare(State(), State(spf: "v=spf1 include:_spf.google.com -all")));

        Assert.Equal("spf", change.RecordType);
        Assert.Equal("warning", change.Severity);
        Assert.Contains("-include:servers.mcsv.net", change.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAddedIncludeIsInformation()
    {
        var change = Assert.Single(DnsDrift.Compare(State(),
            State(spf: "v=spf1 include:_spf.google.com include:servers.mcsv.net include:sendgrid.net -all")));

        Assert.Equal("info", change.Severity);
        Assert.Contains("+include:sendgrid.net", change.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void LooseningAllIsAWarning()
    {
        var change = Assert.Single(DnsDrift.Compare(State(),
            State(spf: "v=spf1 include:_spf.google.com include:servers.mcsv.net ~all")));

        Assert.Equal("warning", change.Severity);
        Assert.Contains("-all → ~all", change.Summary, StringComparison.Ordinal);
    }

    /// <summary>RFC 7208 section 4.5: two SPF records is permerror, so every check fails.</summary>
    [Fact]
    public void ASecondSpfRecordIsCritical()
    {
        var change = Assert.Single(DnsDrift.Compare(State(), State(spfCount: 2)));

        Assert.Equal("critical", change.Severity);
    }

    [Fact]
    public void RemovingSpfIsCritical()
    {
        Assert.Equal("critical", Assert.Single(DnsDrift.Compare(State(), State(spf: null))).Severity);
    }

    /// <summary>Loosening the policy lets forgeries through.</summary>
    [Fact]
    public void AWeakerPolicyIsCritical()
    {
        var change = Assert.Single(DnsDrift.Compare(State(),
            State(dmarc: "v=DMARC1; p=none; rua=mailto:dmarc@msp.example")));

        Assert.Equal("dmarc", change.RecordType);
        Assert.Equal("critical", change.Severity);
        Assert.Contains("p=reject → p=none", change.Summary, StringComparison.Ordinal);
    }

    /// <summary>Right direction, and also the one that starts refusing a client's own mis-sent mail.</summary>
    [Fact]
    public void AStricterPolicyIsAWarning()
    {
        var change = Assert.Single(DnsDrift.Compare(
            State(dmarc: "v=DMARC1; p=none; rua=mailto:dmarc@msp.example"),
            State(dmarc: "v=DMARC1; p=quarantine; rua=mailto:dmarc@msp.example")));

        Assert.Equal("warning", change.Severity);
    }

    /// <summary>Without the report address, this product goes blind to the domain - and looks healthy.</summary>
    [Fact]
    public void LosingTheReportAddressIsCritical()
    {
        var removed = Assert.Single(DnsDrift.Compare(State(), State(dmarc: "v=DMARC1; p=reject")));
        var moved = Assert.Single(DnsDrift.Compare(State(), State(dmarc: "v=DMARC1; p=reject; rua=mailto:reports@other.example")));

        Assert.Equal("critical", removed.Severity);
        Assert.Contains("reports (rua) removed", removed.Summary, StringComparison.Ordinal);
        Assert.Equal("critical", moved.Severity);
    }

    [Fact]
    public void AddingASecondReportAddressIsInformation()
    {
        var change = Assert.Single(DnsDrift.Compare(State(),
            State(dmarc: "v=DMARC1; p=reject; rua=mailto:dmarc@msp.example,mailto:agg@vendor.example")));

        Assert.Equal("info", change.Severity);
    }

    [Fact]
    public void RemovingDmarcIsCritical()
    {
        Assert.Equal("critical", Assert.Single(DnsDrift.Compare(State(), State(dmarc: null))).Severity);
    }

    [Fact]
    public void RemovingMtaStsOrTlsRptIsAWarning()
    {
        var changes = DnsDrift.Compare(State(), State(mtaSts: null, tlsRpt: null));

        Assert.Equal(2, changes.Count);
        Assert.All(changes, c => Assert.Equal("warning", c.Severity));
    }

    [Fact]
    public void ReformattingIsNotSoldAsAChangeOfMeaning()
    {
        var change = Assert.Single(DnsDrift.Compare(State(),
            State(dmarc: "v=DMARC1;p=reject;rua=mailto:dmarc@msp.example")));

        Assert.Equal("info", change.Severity);
        Assert.Contains("same meaning", change.Summary, StringComparison.Ordinal);
    }
}
