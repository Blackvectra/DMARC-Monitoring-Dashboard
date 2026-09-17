using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Rollout;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Rollout;

/// <summary>
/// The order an operator reads the fleet in.
///
/// RolloutAssessment decides what each domain needs and is tested against
/// every combination; this decides which of them is read first, and which
/// appear at all. Both matter: a domain losing mail that sorts below twelve
/// healthy ones is a domain nobody opens, and a domain that has gone silent
/// disappearing from the list entirely is worse still, because silence is the
/// one state the page exists to surface.
/// </summary>
public sealed class TriageServiceTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-triage-{Guid.NewGuid():N}.db");
    private readonly ReportStore _store;

    public TriageServiceTests()
    {
        _store = new ReportStore(_dbPath);
        _store.InitialiseAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    private static string Row(string ip, int count, string dmarc, string domain) => $"""
        <record>
            <row>
              <source_ip>{ip}</source_ip>
              <count>{count}</count>
              <policy_evaluated><disposition>none</disposition><dkim>{dmarc}</dkim><spf>{dmarc}</spf></policy_evaluated>
            </row>
            <identifiers><header_from>{domain}</header_from></identifiers>
            <auth_results>
              <dkim><domain>{domain}</domain><result>{dmarc}</result></dkim>
              <spf><domain>{domain}</domain><result>{dmarc}</result></spf>
            </auth_results>
          </record>
        """;

    private async Task StoreAsync(string domain, string policy, int daysAgo = 1, params string[] rows)
    {
        var begin = DateTimeOffset.UtcNow.AddDays(-daysAgo);
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>google.com</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin>
                            <end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>{domain}</domain><p>{policy}</p><pct>100</pct></policy_published>
              {string.Join("\n  ", rows)}
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await _store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

    private Task<IReadOnlyList<DomainTriage>> GetAsync(int days = 30) =>
        new TriageService(_dbPath).GetAsync(days);

    // ---- what comes first ----------------------------------------------------

    [Fact]
    public async Task ADomainLosingMailNowOutranksEveryHealthyOne()
    {
        // The whole reason this is a ranking rather than an average: one
        // domain at 20% among twelve at 100% averages to something healthy,
        // and the broken one is what somebody opened the page to find.
        await StoreAsync("healthy-a.com", "reject", 1, Row("192.0.2.1", 5000, "pass", "healthy-a.com"));
        await StoreAsync("healthy-b.com", "reject", 1, Row("192.0.2.2", 5000, "pass", "healthy-b.com"));
        await StoreAsync("burning.com", "reject", 1,
            Row("192.0.2.3", 200, "pass", "burning.com"),
            Row("203.0.113.9", 800, "fail", "burning.com"));

        var rows = await GetAsync();

        Assert.Equal("burning.com", rows[0].Domain);
        Assert.Equal(TriageLevel.Urgent, rows[0].Level);
    }

    [Fact]
    public async Task BetweenTwoEquallyUrgentDomainsTheOneLosingMoreMailIsFirst()
    {
        await StoreAsync("small.com", "reject", 1,
            Row("192.0.2.1", 10, "pass", "small.com"),
            Row("203.0.113.9", 40, "fail", "small.com"));
        await StoreAsync("large.com", "reject", 1,
            Row("192.0.2.2", 100, "pass", "large.com"),
            Row("203.0.113.9", 900, "fail", "large.com"));

        var rows = await GetAsync();

        Assert.Equal("large.com", rows[0].Domain);
    }

    [Fact]
    public async Task EveryRowCarriesTheSentenceRolloutAssessmentWouldGive()
    {
        // The list must not paraphrase the judgement, or the list and the
        // domain page end up describing the same domain differently.
        await StoreAsync("acme.com", "reject", 1,
            Row("192.0.2.1", 800, "pass", "acme.com"),
            Row("203.0.113.9", 200, "fail", "acme.com"));

        var row = Assert.Single(await GetAsync());

        var expected = RolloutAssessment.Assess(new DomainState
        {
            Domain = row.Domain,
            Policy = row.Policy,
            PolicyTarget = row.PolicyTarget,
            Messages = row.Messages,
            Passing = row.Passing,
            FailingSources = row.FailingSources,
            LastReport = row.LastReport,
            BaselineStarted = row.BaselineStarted,
            BaselineDays = row.BaselineDays,
        });

        Assert.Equal(expected.Level, row.Level);
        Assert.Equal(expected.Headline, row.Headline);
    }

    // ---- what must not disappear ---------------------------------------------

    [Fact]
    public async Task ADomainThatHasGoneSilentStaysOnTheList()
    {
        // The case an inner join would delete. A domain with no reports inside
        // the window is one of the most important things on this page, and
        // dropping it makes the fleet look smaller and healthier than it is.
        await StoreAsync("gone-quiet.com", "reject", 90, Row("192.0.2.1", 100, "pass", "gone-quiet.com"));
        await StoreAsync("healthy.com", "reject", 1, Row("192.0.2.2", 100, "pass", "healthy.com"));

        var rows = await GetAsync(30);

        Assert.Equal(2, rows.Count);
        var quiet = Assert.Single(rows, r => r.Domain == "gone-quiet.com");
        Assert.Equal(0, quiet.Messages);
        Assert.NotEqual(TriageLevel.Fine, quiet.Level);
        Assert.Contains("No reports", quiet.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ASilentDomainOutranksOneThatIsMerelyFailing()
    {
        // Every other judgement is computed from reports. If those stopped,
        // everything below is describing the past.
        await StoreAsync("silent.com", "reject", 90, Row("192.0.2.1", 100, "pass", "silent.com"));
        await StoreAsync("failing.com", "none", 1,
            Row("192.0.2.2", 90, "pass", "failing.com"),
            Row("203.0.113.9", 10, "fail", "failing.com"));

        var rows = await GetAsync(30);

        Assert.Equal("silent.com", rows[0].Domain);
    }

    // ---- the figures ----------------------------------------------------------

    [Fact]
    public async Task CountsFailingSourcesRatherThanFailingReports()
    {
        // The headline says "from N source(s)", and counting rows instead
        // would inflate it every time a receiver split a source across reports.
        await StoreAsync("acme.com", "reject", 1,
            Row("203.0.113.9", 10, "fail", "acme.com"),
            Row("203.0.113.9", 10, "fail", "acme.com"),
            Row("198.51.100.7", 10, "fail", "acme.com"));

        var row = Assert.Single(await GetAsync());

        Assert.Equal(2, row.FailingSources);
        Assert.Equal(30, row.Messages);
    }

    [Fact]
    public async Task OnlyCountsWhatFallsInsideTheWindow()
    {
        await StoreAsync("acme.com", "reject", 60, Row("192.0.2.1", 1000, "pass", "acme.com"));
        await StoreAsync("acme.com", "reject", 1, Row("192.0.2.1", 7, "pass", "acme.com"));

        var row = Assert.Single(await GetAsync(30));

        Assert.Equal(7, row.Messages);
    }

    [Fact]
    public async Task NamesTheClientADomainBelongsTo()
    {
        await StoreAsync("acme.com", "reject", 1, Row("192.0.2.1", 10, "pass", "acme.com"));
        var slug = await _store.CreateClientAsync("Acme Corp");
        await _store.AssignDomainAsync("acme.com", slug!);

        var row = Assert.Single(await GetAsync());

        Assert.Equal("Acme Corp", row.ClientName);
    }

    [Fact]
    public async Task ReturnsNothingRatherThanThrowingOnAnEmptyDatabase() =>
        Assert.Empty(await GetAsync());
}
