using DmarcMonitor.Core.Domains;
using DmarcMonitor.Core.Intelligence;

namespace DmarcMonitor.Core.Tests.Intelligence;

public sealed class SourceRangesTests
{
    [Theory]
    [InlineData("2a01:111:f403:c112::5", "Microsoft 365")]
    [InlineData("40.107.22.100", "Microsoft 365")]
    [InlineData("209.85.220.41", "Google")]
    [InlineData("2607:f8b0:4864:20::735", "Google")]
    [InlineData("147.160.167.14", "KnowBe4")]
    [InlineData("23.21.109.212", "KnowBe4")]
    [InlineData("198.2.144.17", "Mailchimp")]
    [InlineData("168.245.103.2", "SendGrid")]
    [InlineData("107.175.243.5", "ColoCrossing")]
    [InlineData("23.94.62.163", "ColoCrossing")]
    [InlineData("::ffff:107.175.243.5", "ColoCrossing")]
    public void AnAddressInAPublishedRangeIsNamed(string ip, string name) =>
        Assert.Equal(name, SourceRanges.Identify(ip)?.Name);

    [Theory]
    [InlineData("203.0.113.9")]
    [InlineData("23.21.109.198")]   // next to KnowBe4's single addresses, not one of them
    [InlineData("107.176.0.1")]     // just past 107.172.0.0/14
    [InlineData("not an address")]
    [InlineData(null)]
    public void AnythingElseIsNotNamed(string? ip) => Assert.Null(SourceRanges.Identify(ip));

    [Fact]
    public void ARangeNamesASourceNothingElseHasNamed() =>
        Assert.Equal("Microsoft 365", new DomainSource { SourceIp = "2a01:111:f403:c112::5" }.Display);

    /// <summary>The range is the vendor's statement; an unconfirmed PTR is the holder's.</summary>
    [Fact]
    public void ARangeOutranksAnUnconfirmedReverseName() =>
        Assert.Equal("ColoCrossing", new DomainSource
        {
            SourceIp = "107.175.243.5",
            ReverseName = "mail.client.example",
            NameConfirmed = false,
        }.Display);
}
