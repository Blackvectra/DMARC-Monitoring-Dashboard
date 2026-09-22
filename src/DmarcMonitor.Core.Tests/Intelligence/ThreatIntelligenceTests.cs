using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Intelligence;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Intelligence;

/// <summary>
/// Telling an attacker apart from the customer's own mail infrastructure.
///
/// This is the strongest claim the product makes and the most damaging one to
/// get wrong. Calling a customer's own mail relay an impersonator sends an
/// operator chasing their own gateway and tells a client somebody is forging
/// them when nobody is; missing a real forger does the opposite. Both are
/// worse than any number being slightly off.
/// </summary>
public sealed class ThreatIntelligenceTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-intel-{Guid.NewGuid():N}.db");
    private readonly ReportStore _store;

    public ThreatIntelligenceTests()
    {
        _store = new ReportStore(_dbPath);
        _store.InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    private static string Row(
        string ip, int count, string dmarc, string headerFrom,
        string dkimDomain, string dkimResult, string selector = "selector1") => $"""
        <record>
            <row>
              <source_ip>{ip}</source_ip>
              <count>{count}</count>
              <policy_evaluated><disposition>none</disposition><dkim>{dmarc}</dkim><spf>fail</spf></policy_evaluated>
            </row>
            <identifiers><header_from>{headerFrom}</header_from></identifiers>
            <auth_results>
              <dkim><domain>{dkimDomain}</domain><selector>{selector}</selector><result>{dkimResult}</result></dkim>
              <spf><domain>{headerFrom}</domain><result>fail</result></spf>
            </auth_results>
          </record>
        """;

    private async Task StoreAsync(string domain, params string[] rows)
    {
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>test.example</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{DateTimeOffset.UtcNow.AddDays(-2).ToUnixTimeSeconds()}</begin>
                            <end>{DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>{domain}</domain><p>none</p><pct>100</pct></policy_published>
              {string.Join("\n  ", rows)}
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await _store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

    private async Task<ThreatIndicator?> IndicatorAsync(string ip)
    {
        var service = new ThreatIntelligenceService(_dbPath);
        await service.RefreshAsync();
        var all = await service.GetIndicatorsAsync();
        return all.FirstOrDefault(i => i.Value == ip);
    }

    // ---- the distinction that matters ---------------------------------------

    [Fact]
    public async Task ARelayThatAlsoSignsSuccessfullyIsNotCalledAForger()
    {
        // Taken from live data. A mail gateway carrying a customer's own
        // outbound signs as the customer, and a proportion of its signatures
        // break in transit. Row by row those failures are indistinguishable
        // from forgery: signed as the target, failed. Judged across the whole
        // address they are not, because a relay also produces signatures that
        // pass and a forger never does.
        await StoreAsync("acme.com",
            Row("35.174.145.124", 176, "pass", "acme.com", "acme.com", "pass"),
            Row("35.174.145.124", 67, "fail", "acme.com", "acme.com", "fail"));

        var indicator = await IndicatorAsync("35.174.145.124");

        Assert.NotNull(indicator);
        Assert.False(indicator!.AttemptedForgery, "a relay with passing signatures was called a forger");
        Assert.Empty(indicator.ForgedSelectors);
    }

    [Fact]
    public async Task ASourceThatOnlyEverFailsSigningAsTheTargetIsAForger()
    {
        // The real thing: signs as the domain it is sending as, never
        // succeeds, because it does not hold the key.
        await StoreAsync("acme.com",
            Row("203.0.113.9", 40, "fail", "acme.com", "acme.com", "fail", "selector2"));

        var indicator = await IndicatorAsync("203.0.113.9");

        Assert.NotNull(indicator);
        Assert.True(indicator!.AttemptedForgery);
        Assert.Contains("selector2", indicator.ForgedSelectors);
        Assert.Equal(IndicatorConfidence.High, indicator.Confidence);
    }

    [Fact]
    public async Task ARelayIsStillNotAForgerWhenItBreaksMoreOftenThanItWorks()
    {
        // ndunited.org in the live data: 5 passing, 598 failing from one relay.
        // The ratio says nothing about intent, so it must not decide this.
        await StoreAsync("acme.com",
            Row("35.174.145.124", 5, "pass", "acme.com", "acme.com", "pass"),
            Row("35.174.145.124", 598, "fail", "acme.com", "acme.com", "fail"));

        var indicator = await IndicatorAsync("35.174.145.124");

        Assert.NotNull(indicator);
        Assert.False(indicator!.AttemptedForgery);
    }

    [Fact]
    public async Task ASuccessForOneDomainDoesNotExcuseForgingAnother()
    {
        // The exemption is per domain, not per address. A relay that genuinely
        // carries acme.com must not thereby be cleared of forging other.com.
        await StoreAsync("acme.com",
            Row("198.51.100.7", 100, "pass", "acme.com", "acme.com", "pass"));
        await StoreAsync("other.com",
            Row("198.51.100.7", 20, "fail", "other.com", "other.com", "fail"));

        var indicator = await IndicatorAsync("198.51.100.7");

        Assert.NotNull(indicator);
        Assert.True(indicator!.AttemptedForgery, "forging a second domain was excused by success on the first");
    }

    [Fact]
    public async Task AMisconfiguredServiceSigningAsItselfIsNotAForger()
    {
        // Mailchimp signing as mailchimpapp.net while the header says
        // acme.com. Never forgery, whatever the result.
        await StoreAsync("acme.com",
            Row("198.51.100.7", 55, "fail", "acme.com", "mailchimpapp.net", "pass", "mc"));

        var indicator = await IndicatorAsync("198.51.100.7");

        Assert.NotNull(indicator);
        Assert.False(indicator!.AttemptedForgery);
        Assert.True(indicator.EverAuthenticated);
    }

    // ---- counts and lists ----------------------------------------------------

    [Fact]
    public async Task TheDomainCountMatchesTheDomainsNamed()
    {
        // A headline reading "2 domain(s)" above a list of three is what
        // happened when the count and the names came from different queries.
        await StoreAsync("a.com", Row("203.0.113.9", 5, "fail", "a.com", "", "fail"));
        await StoreAsync("b.com", Row("203.0.113.9", 5, "fail", "b.com", "", "fail"));
        await StoreAsync("c.com", Row("203.0.113.9", 5, "fail", "c.com", "", "fail"));

        var indicator = await IndicatorAsync("203.0.113.9");

        Assert.NotNull(indicator);
        Assert.Equal(indicator!.Domains.Count, indicator.DomainCount);
        Assert.Equal(3, indicator.DomainCount);
    }

    [Fact]
    public async Task ASourceAgainstSeveralDomainsThatNeverAuthenticatesRatesHigh()
    {
        await StoreAsync("a.com", Row("203.0.113.9", 5, "fail", "a.com", "", "fail"));
        await StoreAsync("b.com", Row("203.0.113.9", 5, "fail", "b.com", "", "fail"));

        var indicator = await IndicatorAsync("203.0.113.9");

        Assert.NotNull(indicator);
        Assert.True(indicator!.IsMultiTarget);
        Assert.False(indicator.EverAuthenticated);
        Assert.Equal(IndicatorConfidence.High, indicator.Confidence);
    }

    [Fact]
    public async Task AnOperatorsVerdictSurvivesARefresh()
    {
        // The whole reason the table is worth keeping: classify a source once
        // and it stays classified as more reports arrive.
        await StoreAsync("acme.com", Row("203.0.113.9", 5, "fail", "acme.com", "acme.com", "fail"));

        var service = new ThreatIntelligenceService(_dbPath);
        await service.RefreshAsync();
        await service.ClassifyAsync("203.0.113.9", IndicatorClassification.KnownGood, "operator", "our own relay");

        await StoreAsync("acme.com", Row("203.0.113.9", 9, "fail", "acme.com", "acme.com", "fail"));
        await service.RefreshAsync();

        var all = await service.GetIndicatorsAsync(includeDismissed: true);
        var indicator = Assert.Single(all, i => i.Value == "203.0.113.9");

        Assert.Equal(IndicatorClassification.KnownGood, indicator.Classification);
        Assert.Equal("our own relay", indicator.Notes);
        Assert.Equal(IndicatorConfidence.NotAThreat, indicator.Confidence);
    }

    // ---- the fleet headline --------------------------------------------------

    [Fact]
    public async Task ADomainThatHasStoppedReportingCountsAsSilent()
    {
        // Counting only domains that NEVER reported said 0 silent while five
        // of ten had not been heard from for between 14 and 128 days. An
        // operator reading that headline is told the fleet is fine at exactly
        // the moment monitoring has stopped for half of it.
        await StoreOldAsync("gone-quiet.com", daysAgo: 60);
        await StoreAsync("healthy.com", Row("192.0.2.25", 10, "pass", "healthy.com", "healthy.com", "pass"));

        var summary = await new ThreatIntelligenceService(_dbPath).GetFleetSummaryAsync();

        Assert.Equal(2, summary.Domains);
        Assert.Equal(1, summary.DomainsSilent);
    }

    /// <summary>Stores a report dated in the past, for the silence tests.</summary>
    private async Task StoreOldAsync(string domain, int daysAgo)
    {
        var begin = DateTimeOffset.UtcNow.AddDays(-daysAgo);
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>test.example</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin>
                            <end>{begin.AddDays(1).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>{domain}</domain><p>none</p><pct>100</pct></policy_published>
              {Row("192.0.2.25", 5, "pass", domain, domain, "pass")}
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await _store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

    [Fact]
    public async Task AClassifiedSourceIsHiddenFromTheDefaultList()
    {
        await StoreAsync("acme.com", Row("203.0.113.9", 5, "fail", "acme.com", "acme.com", "fail"));

        var service = new ThreatIntelligenceService(_dbPath);
        await service.RefreshAsync();
        await service.ClassifyAsync("203.0.113.9", IndicatorClassification.KnownGood, "operator");

        Assert.DoesNotContain(await service.GetIndicatorsAsync(), i => i.Value == "203.0.113.9");
    }

    /// <summary>
    /// The wording of the strongest accusation this product makes.
    /// </summary>
    /// <remarks>
    /// It used to read "A misconfigured sender signs as itself; only a forger
    /// signs as its target", which is not true. A mail security gateway that
    /// re-signs in transit signs as the domain it is carrying and breaks its
    /// own signature doing it - character for character what this detects.
    /// Seen on a real estate: one address against two clients, rated High
    /// with that sentence, reversing to a Check Point Harmony host.
    ///
    /// Reporting a customer's own security vendor as an attacker is the way
    /// an operator loses a customer's trust in the tool and then in the
    /// finding that was real.
    /// </remarks>
    [Fact]
    public async Task TheForgeryRationaleOffersBothExplanations()
    {
        await StoreAsync("acme.com", Row("203.0.113.44", 6, "fail", "acme.com", "acme.com", "fail", "selector1"));

        var indicator = await IndicatorAsync("203.0.113.44");

        Assert.True(indicator!.AttemptedForgery);
        Assert.Contains("gateway re-signing", indicator.Rationale, StringComparison.Ordinal);
        Assert.DoesNotContain("only a forger", indicator.Rationale, StringComparison.Ordinal);

        // And it names the question that separates them, because an operator
        // can answer "does this customer use a gateway" and cannot answer
        // "is this a forger".
        Assert.Contains("Ask whether", indicator.Rationale, StringComparison.Ordinal);
    }

    /// <summary>
    /// The rating is deliberately untouched. A PTR is written by whoever
    /// holds the address and is not forward-confirmed, so a friendly name is
    /// not evidence and must never soften a verdict - only the wording of it.
    /// </summary>
    [Fact]
    public async Task SofteningTheWordingDoesNotSoftenTheRating()
    {
        await StoreAsync("acme.com", Row("203.0.113.45", 6, "fail", "acme.com", "acme.com", "fail", "selector1"));

        var indicator = await IndicatorAsync("203.0.113.45");

        Assert.Equal(IndicatorConfidence.High, indicator!.Confidence);
    }
}
