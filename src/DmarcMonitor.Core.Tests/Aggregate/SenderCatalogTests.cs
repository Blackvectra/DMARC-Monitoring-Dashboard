using DmarcMonitor.Core.Aggregate;

namespace DmarcMonitor.Core.Tests.Aggregate;

/// <summary>
/// Naming the service an address belongs to.
///
/// The risk here is not missing a service, which costs a row in a table; it
/// is naming the wrong one, because "Microsoft 365" printed beside an
/// intruder's address reads as reassurance. So the cases that matter most are
/// the ones that must NOT match.
/// </summary>
public sealed class SenderCatalogTests
{
    [Theory]
    // The addresses that filled a real client's report: Microsoft's, in both
    // families, taken from that month's data.
    [InlineData("2a01:111:f403:c10d::1", "Microsoft 365")]
    [InlineData("2a01:111:f400:7e1a::305", "Microsoft 365")]
    [InlineData("40.107.220.66", "Microsoft 365")]
    [InlineData("104.47.55.108", "Microsoft 365")]
    [InlineData("52.101.42.7", "Microsoft 365")]
    [InlineData("209.85.220.41", "Google Workspace")]
    [InlineData("2607:f8b0:4864:20::42c", "Google Workspace")]
    [InlineData("149.72.129.100", "SendGrid")]
    [InlineData("205.139.110.120", "Mimecast")]
    public void NamesTheServiceAnAddressBelongsTo(string ip, string expected) =>
        Assert.Equal(expected, SenderCatalog.Identify(ip));

    [Theory]
    // Neighbours of the ranges above, one step outside. A prefix compared a
    // byte too loosely swallows these, and the wrong name on a stranger's
    // address is the failure this whole thing has to avoid.
    [InlineData("40.106.255.255")]       // just below 40.107.0.0/16
    [InlineData("40.108.0.0")]           // just above
    [InlineData("104.47.128.0")]         // just above 104.47.0.0/17
    [InlineData("2a01:111:f402::1")]     // adjacent /48, not Microsoft's
    [InlineData("35.174.145.124")]       // the cross-client source in real data
    [InlineData("74.208.24.40")]
    [InlineData("8.8.8.8")]
    public void SaysNothingAboutAnAddressItDoesNotKnow(string ip) =>
        Assert.Null(SenderCatalog.Identify(ip));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("not-an-address")]
    [InlineData("999.999.999.999")]
    public void RubbishIsNotAService(string? value)
    {
        Assert.Null(SenderCatalog.Identify(value));
        Assert.Equal((value ?? "").Trim(), SenderCatalog.Label(value));
    }

    [Fact]
    public void AnUnknownAddressIsLabeledWithItself()
    {
        // Label never invents a name, because a row saying "unknown service"
        // for eleven different addresses would merge eleven strangers into
        // one line.
        Assert.Equal("35.174.145.124", SenderCatalog.Label("35.174.145.124"));
        Assert.Equal("Microsoft 365", SenderCatalog.Label("40.107.220.66"));
    }

    [Fact]
    public void AFamilyIsNeverMatchedAgainstTheOther()
    {
        // A v4 address whose bytes happen to align with the head of a v6
        // prefix must not match it, and the reverse.
        Assert.Null(SenderCatalog.Identify("42.1.17.244"));
        Assert.NotEqual("Google Workspace", SenderCatalog.Identify("38.7.248.176"));
    }
}
