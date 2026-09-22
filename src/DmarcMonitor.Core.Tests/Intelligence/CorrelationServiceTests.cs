using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Intelligence;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Intelligence;

/// <summary>
/// The verdict the sources list puts in front of an operator.
///
/// This is the third place that classifies a sending source, alongside the
/// client report and the threat intelligence, and it was the only one without
/// tests. That is precisely where the day's worst regression landed: a first
/// attempt at excusing a customer's own mail relay exempted any address that
/// had ever passed anywhere in the fleet, which cleared a genuine forger. It
/// was caught only because this page and the intelligence disagreed about one
/// address. These tests remove the reliance on that coincidence.
/// </summary>
public sealed class CorrelationServiceTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-corr-{Guid.NewGuid():N}.db");
    private readonly ReportStore _store;

    public CorrelationServiceTests()
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

    private static string Row(string ip, int count, string dmarc, string domain, string dkimResult) => $"""
        <record>
            <row>
              <source_ip>{ip}</source_ip>
              <count>{count}</count>
              <policy_evaluated><disposition>none</disposition><dkim>{dmarc}</dkim><spf>fail</spf></policy_evaluated>
            </row>
            <identifiers><header_from>{domain}</header_from></identifiers>
            <auth_results>
              <dkim><domain>{domain}</domain><selector>selector1</selector><result>{dkimResult}</result></dkim>
              <spf><domain>{domain}</domain><result>fail</result></spf>
            </auth_results>
          </record>
        """;

    /// <summary>A row where the source signs as its OWN domain, not the sender's.</summary>
    private static string ThirdPartyRow(string ip, int count, string headerFrom, string signsAs) => $"""
        <record>
            <row>
              <source_ip>{ip}</source_ip>
              <count>{count}</count>
              <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
            </row>
            <identifiers><header_from>{headerFrom}</header_from></identifiers>
            <auth_results>
              <dkim><domain>{signsAs}</domain><selector>mc</selector><result>pass</result></dkim>
              <spf><domain>{signsAs}</domain><result>pass</result></spf>
            </auth_results>
          </record>
        """;

    /// <summary>
    /// A domain nobody has onboarded, which is how every domain starts.
    /// </summary>
    private Task StoreUnassignedAsync(string domain, params string[] rows) =>
        StoreAsync(domain, clientSlug: null, rows);

    private async Task StoreAsync(string domain, string? clientSlug, params string[] rows)
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

        // Each domain to its own client, so cross-client counting is real.
        // Passing null leaves it where an import leaves it - in the Unassigned
        // bucket - which is the state every real install starts in and which
        // no test here used to cover.
        if (clientSlug is null) { return; }

        await _store.CreateClientAsync(clientSlug, clientSlug);
        await _store.AssignDomainAsync(domain, clientSlug);
    }

    private async Task<FailingSource?> SourceAsync(string ip)
    {
        var rows = await new CorrelationService(_dbPath).GetFailingSourcesAsync();
        return rows.FirstOrDefault(r => r.SourceIp == ip);
    }

    [Fact]
    public async Task SeesImpersonationAcrossDomainsNobodyHasOnboardedYet()
    {
        // Cross-client impersonation is the one finding only a multi-client
        // platform can make, and it was unreachable on a fresh install. Every
        // imported domain lands in the single Unassigned bucket, the check
        // counted rows in the clients table, and so every source looked like
        // it touched exactly one client no matter how many domains it was
        // forging. On the live database one address was hitting twelve of the
        // eighteen domains and was reported as touching one client.
        await StoreUnassignedAsync("a.example", Row("203.0.113.9", 5, "fail", "a.example", "fail"));
        await StoreUnassignedAsync("b.example", Row("203.0.113.9", 5, "fail", "b.example", "fail"));
        await StoreUnassignedAsync("c.example", Row("203.0.113.9", 5, "fail", "c.example", "fail"));

        var source = await SourceAsync("203.0.113.9");

        Assert.NotNull(source);
        Assert.Equal(3, source!.IndependentParties);
        Assert.True(source.IsCrossClient, "three unfiled domains are three unrelated parties, not one client");
        Assert.Equal(SourceVerdict.CrossClientImpersonation, source.Verdict);
    }

    [Fact]
    public async Task OneUnassignedDomainIsStillOnlyOneParty()
    {
        // The other side of it: the fallback must not turn a single domain
        // into a campaign just because nobody has filed it yet.
        await StoreUnassignedAsync("only.example", Row("203.0.113.9", 5, "fail", "only.example", "fail"));

        var source = await SourceAsync("203.0.113.9");

        Assert.NotNull(source);
        Assert.Equal(1, source!.IndependentParties);
        Assert.False(source.IsCrossClient);
    }

    // ---- the regression this file exists for ---------------------------------

    [Fact]
    public async Task AnAddressPassingForOneClientIsStillForgingTheOthers()
    {
        // 3.231.237.226 in the live data: two passing messages for one client,
        // failing as three others it has never passed for. A fleet-wide "has
        // it ever passed" test cleared it entirely, which is the single most
        // dangerous outcome available here - a real forger marked benign.
        await StoreAsync("carried.com", "carried",
            Row("3.231.237.226", 2, "pass", "carried.com", "pass"));
        await StoreAsync("forged-a.com", "forged-a",
            Row("3.231.237.226", 10, "fail", "forged-a.com", "fail"));
        await StoreAsync("forged-b.com", "forged-b",
            Row("3.231.237.226", 2, "fail", "forged-b.com", "fail"));

        var source = await SourceAsync("3.231.237.226");

        Assert.NotNull(source);
        Assert.False(source!.IsOwnSendingPath, "passing for one client cleared it of forging two others");
        Assert.Equal(SourceVerdict.CrossClientImpersonation, source.Verdict);
    }

    [Fact]
    public async Task ARelayPassingForEveryDomainItTouchesIsNotImpersonation()
    {
        // The customer's own gateway: signs for each of them, breaks a share
        // of its signatures in transit. Judged on the failing rows alone it
        // reads as somebody sending as all of them at once.
        await StoreAsync("one.com", "client-one",
            Row("35.174.145.124", 176, "pass", "one.com", "pass"),
            Row("35.174.145.124", 67, "fail", "one.com", "fail"));
        await StoreAsync("two.com", "client-two",
            Row("35.174.145.124", 113, "pass", "two.com", "pass"),
            Row("35.174.145.124", 239, "fail", "two.com", "fail"));

        var source = await SourceAsync("35.174.145.124");

        Assert.NotNull(source);
        Assert.True(source!.IsOwnSendingPath);
        Assert.Equal(SourceVerdict.Misconfigured, source.Verdict);
    }

    [Fact]
    public async Task ASourceThatNeverPassesAnywhereIsImpersonation()
    {
        await StoreAsync("a.com", "client-a", Row("203.0.113.9", 5, "fail", "a.com", "fail"));
        await StoreAsync("b.com", "client-b", Row("203.0.113.9", 5, "fail", "b.com", "fail"));

        var source = await SourceAsync("203.0.113.9");

        Assert.NotNull(source);
        Assert.False(source!.IsOwnSendingPath);
        Assert.True(source.IsCrossClient);
        Assert.Equal(SourceVerdict.CrossClientImpersonation, source.Verdict);
    }

    [Fact]
    public async Task ASingleDomainWithNothingProvedIsNotYetCalledACampaign()
    {
        // One client is noise. Calling it a campaign is how the page starts
        // crying wolf and stops being read.
        await StoreAsync("a.com", "client-a", Row("203.0.113.9", 5, "fail", "a.com", "fail"));

        var source = await SourceAsync("203.0.113.9");

        Assert.NotNull(source);
        Assert.False(source!.IsCrossClient);
        Assert.Equal(SourceVerdict.Unauthenticated, source.Verdict);
    }

    [Fact]
    public async Task AThirdPartyServiceSigningAsItselfIsMisconfigured()
    {
        await StoreAsync("acme.com", "acme",
            ThirdPartyRow("198.51.100.7", 55, "acme.com", "mailchimpapp.net"));

        var source = await SourceAsync("198.51.100.7");

        Assert.NotNull(source);
        Assert.Contains("mailchimpapp.net", source!.AuthenticatedFor);
        Assert.Equal(SourceVerdict.Misconfigured, source.Verdict);
    }

    // ---- the counts the page prints ------------------------------------------

    [Fact]
    public async Task CountsClientsAndDomainsFromWhatItNames()
    {
        await StoreAsync("a.com", "client-a", Row("203.0.113.9", 5, "fail", "a.com", "fail"));
        await StoreAsync("b.com", "client-b", Row("203.0.113.9", 5, "fail", "b.com", "fail"));

        var source = await SourceAsync("203.0.113.9");

        Assert.NotNull(source);
        Assert.Equal(source!.Domains.Count, source.DomainCount);
        Assert.Equal(source.Clients.Count, source.ClientCount);
        Assert.Equal(10, source.FailedMessages);
    }

    [Fact]
    public async Task IgnoresAForwarderThatDeclaredItselfAnOverride()
    {
        // A mailing list breaking authentication is expected behavior, and
        // including it buries the findings that matter under traffic nobody
        // should act on.
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>test.example</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{DateTimeOffset.UtcNow.AddDays(-2).ToUnixTimeSeconds()}</begin>
                            <end>{DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>acme.com</domain><p>none</p><pct>100</pct></policy_published>
              <record>
                <row>
                  <source_ip>192.0.2.50</source_ip>
                  <count>40</count>
                  <policy_evaluated>
                    <disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
                    <reason><type>forwarded</type><comment>mailing list</comment></reason>
                  </policy_evaluated>
                </row>
                <identifiers><header_from>acme.com</header_from></identifiers>
                <auth_results>
                  <dkim><domain>acme.com</domain><result>fail</result></dkim>
                  <spf><domain>acme.com</domain><result>fail</result></spf>
                </auth_results>
              </record>
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await _store.SaveAggregateAsync(parsed.Report!, xml, null);

        Assert.Null(await SourceAsync("192.0.2.50"));
    }

    /// <summary>
    /// The row an operator actually reads.
    /// </summary>
    /// <remarks>
    /// "192.3.180.38 against two clients" is homework. "ColoCrossing against
    /// two clients" is a finding, and it is the same row.
    /// </remarks>
    [Fact]
    public async Task ASourceWithAKnownReverseNameIsReportedByVendorName()
    {
        await StoreUnassignedAsync("a.example", Row("35.174.145.124", 5, "fail", "a.example", "fail"));
        await new SourceNameStore(_dbPath).SaveAsync("35.174.145.124", "us.cloud-sec-av.com", answered: true);

        var row = await SourceAsync("35.174.145.124");

        Assert.NotNull(row);
        Assert.True(row!.IsNamed);
        Assert.Equal("us.cloud-sec-av.com", row.ReverseName);

        // The address is still the identity; only the label changed.
        Assert.Equal("35.174.145.124", row.SourceIp);
        Assert.NotEqual(row.SourceIp, row.Display);
    }

    /// <summary>
    /// The state every install is in for its first night, and the one that
    /// must not look broken: nothing has been looked up yet.
    /// </summary>
    [Fact]
    public async Task ASourceNobodyHasLookedUpStillReportsItsAddress()
    {
        await StoreUnassignedAsync("a.example", Row("203.0.113.77", 5, "fail", "a.example", "fail"));

        var row = await SourceAsync("203.0.113.77");

        Assert.NotNull(row);
        Assert.Null(row!.ReverseName);
        Assert.False(row.IsNamed);
        Assert.Equal("203.0.113.77", row.Display);
    }

    /// <summary>
    /// A reverse name the catalogue has never seen is still worth showing: it
    /// is a domain somebody can search for, where an address is not.
    /// </summary>
    [Fact]
    public async Task AnUnrecognisedReverseNameIsShownRatherThanDiscarded()
    {
        await StoreUnassignedAsync("a.example", Row("198.51.100.4", 5, "fail", "a.example", "fail"));
        await new SourceNameStore(_dbPath).SaveAsync("198.51.100.4", "smtp3.some-isp.example", answered: true);

        var row = await SourceAsync("198.51.100.4");

        Assert.Equal("smtp3.some-isp.example", row!.Display);
    }

    /// <summary>
    /// Naming is for reading, never for judging. A PTR is written by whoever
    /// holds the address, so a friendly name is not evidence of anything -
    /// and a source that authenticated nothing against several unrelated
    /// parties stays exactly as damning with a name on it.
    /// </summary>
    [Fact]
    public async Task ANameDoesNotSoftenTheVerdict()
    {
        await StoreAsync("a.example", "alpha", Row("192.0.2.200", 5, "fail", "a.example", "fail"));
        await StoreAsync("b.example", "beta", Row("192.0.2.200", 5, "fail", "b.example", "fail"));

        var before = await SourceAsync("192.0.2.200");
        await new SourceNameStore(_dbPath).SaveAsync("192.0.2.200", "mail.colocrossing.com", answered: true);
        var after = await SourceAsync("192.0.2.200");

        Assert.True(after!.IsNamed);
        Assert.Equal(before!.Verdict, after.Verdict);
        Assert.Equal(before.IsCrossClient, after.IsCrossClient);
        Assert.Equal(before.IndependentParties, after.IndependentParties);
    }
}
