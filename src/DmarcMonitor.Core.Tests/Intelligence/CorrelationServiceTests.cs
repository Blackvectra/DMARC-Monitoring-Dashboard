using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Intelligence;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tests.Storage;
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

    /// <summary>A failing row the receiver says it overrode, as a forwarder or mailing list produces.</summary>
    private static string ForwardedRow(string ip, int count, string domain) => $"""
        <record>
            <row>
              <source_ip>{ip}</source_ip>
              <count>{count}</count>
              <policy_evaluated>
                <disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
                <reason><type>forwarded</type><comment>mailing list</comment></reason>
              </policy_evaluated>
            </row>
            <identifiers><header_from>{domain}</header_from></identifiers>
            <auth_results>
              <dkim><domain>{domain}</domain><result>fail</result></dkim>
              <spf><domain>{domain}</domain><result>fail</result></spf>
            </auth_results>
          </record>
        """;

    /// <summary>
    /// A domain nobody has onboarded, which is how every domain starts.
    /// </summary>
    private Task StoreUnassignedAsync(string domain, params string[] rows) =>
        StoreAsync(domain, clientSlug: null, rows);

    private Task StoreAsync(string domain, string? clientSlug, params string[] rows) =>
        StoreAsync(domain, clientSlug, daysAgo: 2, rows);

    /// <param name="daysAgo">How long ago the report's window began; the sources list looks back thirty days.</param>
    private async Task StoreAsync(string domain, string? clientSlug, int daysAgo, params string[] rows)
    {
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>test.example</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{DateTimeOffset.UtcNow.AddDays(-daysAgo).ToUnixTimeSeconds()}</begin>
                            <end>{DateTimeOffset.UtcNow.AddDays(-daysAgo + 1).ToUnixTimeSeconds()}</end></date_range>
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

    /// <summary>
    /// What the cut at the limit keeps, since a sender is built from the
    /// addresses that survive it: the widest-reaching first, then the busiest,
    /// and among equals the same ones every time.
    /// </summary>
    [Fact]
    public async Task TheLimitKeepsTheWidestThenTheBusiestAndAmongEqualsTheSameOnesEveryTime()
    {
        // Three addresses that reached one party and sent one message each...
        foreach (var ip in new[] { "203.0.113.3", "203.0.113.2", "203.0.113.1" })
        {
            await StoreUnassignedAsync("only.example", Row(ip, 1, "fail", "only.example", "fail"));
        }

        // ...one that was busier, and one that reached two parties.
        await StoreUnassignedAsync("only.example", Row("203.0.113.60", 9, "fail", "only.example", "fail"));
        await StoreUnassignedAsync("wide-a.example", Row("203.0.113.50", 1, "fail", "wide-a.example", "fail"));
        await StoreUnassignedAsync("wide-b.example", Row("203.0.113.50", 1, "fail", "wide-b.example", "fail"));

        var service = new CorrelationService(_dbPath);

        var first = await service.GetFailingSourcesAsync(limit: 3);
        var again = await service.GetFailingSourcesAsync(limit: 3);

        Assert.Equal(["203.0.113.50", "203.0.113.60", "203.0.113.1"], first.Select(s => s.SourceIp));
        Assert.Equal(first.Select(s => s.SourceIp), again.Select(s => s.SourceIp));
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

    /// <summary>
    /// Which parties, not only how many: the page groups addresses into
    /// senders, and what a sender reached is the union of what its addresses
    /// did. A client and an unfiled domain are told apart even when one is
    /// named like the other.
    /// </summary>
    [Fact]
    public async Task NamesTheParties()
    {
        await StoreAsync("a.example", "alpha", Row("203.0.113.9", 5, "fail", "a.example", "fail"));
        await StoreAsync("b.example", "beta", Row("203.0.113.9", 5, "fail", "b.example", "fail"));
        await StoreUnassignedAsync("c.example", Row("203.0.113.9", 5, "fail", "c.example", "fail"));

        var source = await SourceAsync("203.0.113.9");

        Assert.NotNull(source);

        // A client is identified by the client, not by what it is called, so
        // the keys are opaque; an unfiled domain is told apart by its name.
        Assert.Equal(3, source!.PartyKeys.Count);
        Assert.Equal(3, source.IndependentParties);
        Assert.Contains("domain:c.example", source.PartyKeys);
        Assert.Equal(2, source.PartyKeys.Count(k => k.StartsWith("client:", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task TwoDomainsOfOneClientAreOnePartyKey()
    {
        // One customer with two domains is one party. A sender that hit both
        // has not worked through two customers.
        await StoreAsync("one.example", "pair", Row("203.0.113.9", 5, "fail", "one.example", "fail"));
        await StoreUnassignedAsync("two.example", Row("203.0.113.9", 5, "fail", "two.example", "fail"));
        await _store.AssignDomainAsync("two.example", "pair");

        var source = await SourceAsync("203.0.113.9");

        Assert.NotNull(source);
        var party = Assert.Single(source!.PartyKeys);
        Assert.StartsWith("client:", party);
        Assert.Equal(2, source.DomainCount);
        Assert.False(source.IsCrossClient);
    }

    /// <summary>
    /// A slug is unique inside an organization, not across them, so with no
    /// organization chosen two clients can carry the same one. They are two
    /// parties: the count already said so, and the keys said one, which left
    /// the row reading "Cross-client" beside "1 party" and made a sender
    /// working through both organizations' customers look like it had
    /// reached a single one.
    /// </summary>
    [Fact]
    public async Task ClientsWithTheSameSlugInTwoOrganizationsAreTwoParties()
    {
        await SeedTwoOrganizationsWithAnAcmeEachAsync("203.0.113.9");

        var source = await SourceAsync("203.0.113.9");

        Assert.NotNull(source);
        Assert.Equal(2, source!.PartyKeys.Count);
        Assert.Equal(2, source.IndependentParties);
        Assert.True(source.IsCrossClient);

        // And the sender made of such addresses agrees with each of them.
        var group = Assert.Single(SenderGroup.Build([source]));
        Assert.Equal(2, group.IndependentParties);
    }

    [Fact]
    public async Task TheSourcePageCountsThemTheSameWay()
    {
        await SeedTwoOrganizationsWithAnAcmeEachAsync("203.0.113.9");

        var listed = await SourceAsync("203.0.113.9");
        var detail = await DetailAsync("203.0.113.9");

        Assert.Equal(2, detail!.IndependentParties);
        Assert.Equal(listed!.IndependentParties, detail.IndependentParties);
        Assert.Equal(SourceVerdict.CrossClientImpersonation, detail.Verdict);
    }

    /// <summary>
    /// Seeded as SQL, the way the tests of the organization boundary are: the
    /// public API files a domain under one organization's clients, and what
    /// is wanted here is the shape the schema allows - UNIQUE(tenant_id, slug)
    /// - with the same slug in two of them.
    /// </summary>
    private async Task SeedTwoOrganizationsWithAnAcmeEachAsync(string ip)
    {
        var when = DateTime.UtcNow.AddDays(-2).ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);

        await SingleDatabase.ExecuteAsync(_dbPath, $"""
            INSERT INTO tenants (id,slug,name,created_at,updated_at)
              VALUES ('t-a','orga','Org A','{when}','{when}'),('t-b','orgb','Org B','{when}','{when}');
            INSERT INTO clients (id,tenant_id,slug,name,created_at,updated_at)
              VALUES ('c-a','t-a','acme','Acme','{when}','{when}'),('c-b','t-b','acme','Acme','{when}','{when}');
            INSERT INTO domains (id,tenant_id,client_id,name,created_at,updated_at)
              VALUES ('d-a','t-a','c-a','a.example','{when}','{when}'),
                     ('d-b','t-b','c-b','b.example','{when}','{when}');
            INSERT INTO aggregate_reports
              (id,tenant_id,client_id,domain_id,org_name,external_report_id,
               date_begin,date_end,raw_hash,received_at,ingested_at,policy_p)
              VALUES ('r-a','t-a','c-a','d-a','test.example','rep-a','{when}','{when}','hash-a','{when}','{when}','none'),
                     ('r-b','t-b','c-b','d-b','test.example','rep-b','{when}','{when}','hash-b','{when}','{when}','none');
            INSERT INTO aggregate_records
              (report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,
               dmarc_result,dkim_auth_result,header_from)
              VALUES ('r-a','t-a','c-a','d-a','{when}','{ip}',4,'fail','fail','a.example'),
                     ('r-b','t-b','c-b','d-b','{when}','{ip}',6,'fail','fail','b.example');
            """);
    }

    /// <summary>
    /// Client names are free text and commas are ordinary in them. Read back
    /// from a comma-joined column, "Acme, Inc." became two clients, "Acme" and
    /// "Inc.", and a search for the second found a sender it had no business
    /// finding.
    /// </summary>
    [Fact]
    public async Task AClientNameWithACommaStaysOneClient()
    {
        await _store.CreateClientAsync("Acme, Inc.", "acme-inc");
        await StoreUnassignedAsync("a.example", Row("203.0.113.9", 5, "fail", "a.example", "fail"));
        await _store.AssignDomainAsync("a.example", "acme-inc");

        var source = await SourceAsync("203.0.113.9");

        Assert.NotNull(source);
        Assert.Equal(["Acme, Inc."], source!.Clients);
        Assert.Equal(1, source.ClientCount);
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

    /// <summary>
    /// "Has sent authenticated mail for every domain it fails against" is a
    /// claim about the window being shown. An address that carried two
    /// clients properly months ago, and now fails with nothing signed only
    /// against a third, has not passed for the third - and clearing it as
    /// one of the client's own paths is the dangerous way to be wrong.
    /// </summary>
    [Fact]
    public async Task PassingLongAgoForOtherDomainsDoesNotClearAnAddressNowFailingForANewOne()
    {
        await StoreAsync("b.example", "beta", daysAgo: 100,
            Row("203.0.113.9", 5, "pass", "b.example", "pass"),
            Row("203.0.113.9", 5, "fail", "b.example", "fail"));
        await StoreAsync("c.example", "gamma", daysAgo: 100,
            Row("203.0.113.9", 5, "pass", "c.example", "pass"),
            Row("203.0.113.9", 5, "fail", "c.example", "fail"));
        await StoreAsync("a.example", "alpha", Row("203.0.113.9", 5, "fail", "a.example", "fail"));

        var source = await SourceAsync("203.0.113.9");

        Assert.NotNull(source);
        Assert.Equal(["a.example"], source!.Domains);
        Assert.False(source.IsOwnSendingPath, "it has never passed for a.example");
        Assert.Equal(SourceReading.Unauthenticated, source.Reading);
    }

    /// <summary>
    /// The pass has to be inside the window too, as it is on the page behind
    /// the address. Otherwise a pass from before the window clears an address
    /// that has not authenticated once in the period being read.
    /// </summary>
    [Fact]
    public async Task APassFromBeforeTheWindowDoesNotMakeAnAddressAnOwnSendingPath()
    {
        await StoreAsync("b.example", "beta", daysAgo: 100, Row("203.0.113.9", 5, "pass", "b.example", "pass"));
        await StoreAsync("b.example", "beta", Row("203.0.113.9", 5, "fail", "b.example", "fail"));

        var listed = await SourceAsync("203.0.113.9");
        var detail = await DetailAsync("203.0.113.9");

        Assert.False(listed!.IsOwnSendingPath);
        Assert.False(detail!.IsOwnSendingPath, "the two pages must agree");
    }

    /// <summary>
    /// And the failure has to be current: a domain the address has stopped
    /// failing against is not one of the domains it is being judged on, so it
    /// cannot stand in for one it is failing against now.
    /// </summary>
    [Fact]
    public async Task ADomainItStoppedFailingAgainstDoesNotVouchForOneItFailsNow()
    {
        await StoreAsync("b.example", "beta", daysAgo: 100, Row("203.0.113.9", 5, "fail", "b.example", "fail"));
        await StoreAsync("b.example", "beta", Row("203.0.113.9", 5, "pass", "b.example", "pass"));
        await StoreAsync("a.example", "alpha", Row("203.0.113.9", 5, "fail", "a.example", "fail"));

        var source = await SourceAsync("203.0.113.9");

        Assert.NotNull(source);
        Assert.Equal(["a.example"], source!.Domains);
        Assert.False(source.IsOwnSendingPath);
    }

    /// <summary>
    /// The same, for failures the list itself does not count: a forwarded
    /// failure is excluded from the findings, so it cannot be what makes
    /// the address look like it passes for everything it is listed against.
    /// </summary>
    [Fact]
    public async Task AFailureTheListIgnoresDoesNotClearAnAddressFailingForAnotherDomain()
    {
        await StoreAsync("b.example", "beta",
            Row("203.0.113.9", 5, "pass", "b.example", "pass"),
            ForwardedRow("203.0.113.9", 5, "b.example"));
        await StoreAsync("a.example", "alpha", Row("203.0.113.9", 5, "fail", "a.example", "fail"));

        var source = await SourceAsync("203.0.113.9");

        Assert.NotNull(source);
        Assert.Equal(["a.example"], source!.Domains);
        Assert.False(source.IsOwnSendingPath);
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
    public async Task AnUnrecognizedReverseNameIsShownRatherThanDiscarded()
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

    // ---- one source, across the whole estate ---------------------------------

    private Task<SourceDetail?> DetailAsync(string ip, string? tenantId = null, string? clientSlug = null) =>
        new CorrelationService(_dbPath).GetSourceAsync(ip, tenantId: tenantId, clientSlug: clientSlug);

    /// <summary>
    /// The finding the page exists for, and the one a single-tenant tool
    /// cannot make: the same address working through unrelated businesses.
    /// </summary>
    [Fact]
    public async Task GathersEveryDomainOneSourceWasSeenAgainst()
    {
        await StoreAsync("a.example", "alpha", Row("192.0.2.10", 5, "fail", "a.example", "fail"));
        await StoreAsync("b.example", "beta", Row("192.0.2.10", 7, "fail", "b.example", "fail"));
        await StoreAsync("c.example", "gamma", Row("192.0.2.10", 3, "fail", "c.example", "fail"));

        var source = await DetailAsync("192.0.2.10");

        Assert.NotNull(source);
        Assert.Equal(3, source!.DomainCount);
        Assert.Equal(3, source.IndependentParties);
        Assert.True(source.IsCrossClient);
        Assert.Equal(15, source.Messages);
        Assert.Equal(15, source.Failing);
    }

    /// <summary>
    /// All traffic, not only the failing rows. A source that authenticates
    /// nine times in ten and fails on the tenth is the commonest real case,
    /// and a page showing only the tenth describes a working mail path as a
    /// threat.
    /// </summary>
    [Fact]
    public async Task CountsThePassingMailToo()
    {
        await StoreAsync("a.example", "alpha",
            Row("192.0.2.11", 90, "pass", "a.example", "pass"),
            Row("192.0.2.11", 10, "fail", "a.example", "fail"));

        var source = await DetailAsync("192.0.2.11");

        Assert.Equal(100, source!.Messages);
        Assert.Equal(90, source.Passing);
        Assert.Equal(10, source.Failing);
    }

    /// <summary>
    /// Per domain, which is the whole value of the column. Passing is what a
    /// forger cannot do - but only for the domain it passed for.
    /// </summary>
    [Fact]
    public async Task RecordsWhetherItEverPassedForEachDomainSeparately()
    {
        await StoreAsync("a.example", "alpha", Row("192.0.2.12", 5, "pass", "a.example", "pass"));
        await StoreAsync("b.example", "beta", Row("192.0.2.12", 5, "fail", "b.example", "fail"));

        var source = await DetailAsync("192.0.2.12");

        Assert.True(source!.Appearances.Single(a => a.Domain == "a.example").EverPassed);
        Assert.False(source.Appearances.Single(a => a.Domain == "b.example").EverPassed);

        // And so it is not a sending path for everything it touches.
        Assert.False(source.IsOwnSendingPath);
    }

    /// <summary>
    /// The two screens must not disagree about one address. An operator who
    /// sees a source called impersonation in a list and misconfiguration on
    /// its own page cannot tell which to believe, which is worse than either
    /// being wrong.
    /// </summary>
    [Fact]
    public async Task AgreesWithTheListAboutTheVerdict()
    {
        await StoreAsync("a.example", "alpha", Row("192.0.2.13", 5, "fail", "a.example", "fail"));
        await StoreAsync("b.example", "beta", Row("192.0.2.13", 5, "fail", "b.example", "fail"));

        var listed = await SourceAsync("192.0.2.13");
        var detail = await DetailAsync("192.0.2.13");

        Assert.Equal(SourceVerdict.CrossClientImpersonation, listed!.Verdict);
        Assert.Equal(listed.Verdict, detail!.Verdict);
        Assert.Equal(listed.IndependentParties, detail.IndependentParties);
        Assert.Equal(SourceReading.CrossClient, detail.Reading);
        Assert.Equal(listed.Reading, detail.Reading);
    }

    /// <summary>
    /// The list splits the benign half of the verdict in two, and the page
    /// behind a name has to call the same address the same thing: an
    /// "Unaligned service" in the list is not "Misconfigured" on its own page.
    /// </summary>
    [Theory]
    [InlineData(SourceReading.OwnSendingPath)]
    [InlineData(SourceReading.Unaligned)]
    [InlineData(SourceReading.Unauthenticated)]
    public async Task ReadsEachKindOfSourceTheSameWayAsTheList(SourceReading expected)
    {
        const string ip = "198.51.100.77";

        switch (expected)
        {
            case SourceReading.OwnSendingPath:
                await StoreAsync("a.example", "alpha",
                    Row(ip, 5, "pass", "a.example", "pass"), Row(ip, 5, "fail", "a.example", "fail"));
                break;

            case SourceReading.Unaligned:
                await StoreAsync("a.example", "alpha", ThirdPartyRow(ip, 5, "a.example", "mailchimpapp.net"));
                break;

            default:
                await StoreAsync("a.example", "alpha", Row(ip, 5, "fail", "a.example", "fail"));
                break;
        }

        var listed = await SourceAsync(ip);
        var detail = await DetailAsync(ip);

        Assert.Equal(expected, listed!.Reading);
        Assert.Equal(expected, detail!.Reading);
    }

    [Fact]
    public async Task NamesTheSourceWhenSomethingHasResolvedIt()
    {
        await StoreAsync("a.example", "alpha", Row("192.0.2.14", 5, "fail", "a.example", "fail"));
        await new SourceNameStore(_dbPath).SaveAsync("192.0.2.14", "us.cloud-sec-av.com", answered: true, forwardConfirmed: true);

        var source = await DetailAsync("192.0.2.14");

        Assert.True(source!.IsNamed);
        Assert.Equal(SourceKind.SecurityGateway, source.Kind);
        Assert.Equal("Avanan (Check Point Harmony)", source.Display);
    }

    /// <summary>
    /// An unconfirmed name is printed as the hostname it claims and decides
    /// nothing: calling it "Avanan" would be this product vouching for a PTR
    /// the sender wrote.
    /// </summary>
    [Fact]
    public async Task AnUnconfirmedNameIsShownButNotBelieved()
    {
        await StoreAsync("a.example", "alpha", Row("192.0.2.15", 5, "fail", "a.example", "fail"));
        await new SourceNameStore(_dbPath).SaveAsync("192.0.2.15", "us.cloud-sec-av.com", answered: true, forwardConfirmed: false);

        var source = await DetailAsync("192.0.2.15");

        Assert.True(source!.IsNamed);
        Assert.Equal("us.cloud-sec-av.com", source.Display);
        Assert.Equal(SourceKind.Unknown, source.Kind);
    }

    /// <summary>
    /// Not an empty page about an address that may not exist.
    /// </summary>
    [Fact]
    public async Task AnAddressWithNoReportsIsNotFound()
    {
        Assert.Null(await DetailAsync("192.0.2.222"));
    }

    /// <summary>
    /// Across one organization's clients is the product; across two
    /// organizations is a leak. The same rule the list obeys.
    /// </summary>
    [Fact]
    public async Task DoesNotReachIntoAnotherOrganization()
    {
        await StoreAsync("a.example", "alpha", Row("192.0.2.15", 5, "fail", "a.example", "fail"));

        Assert.Null(await DetailAsync("192.0.2.15", tenantId: "another-organization"));
    }

    /// <summary>
    /// A customer's own login sees their own domain and not the six others
    /// the same address was seen against.
    /// </summary>
    [Fact]
    public async Task ACustomerSeesOnlyTheirOwnDomain()
    {
        await StoreAsync("a.example", "alpha", Row("192.0.2.16", 5, "fail", "a.example", "fail"));
        await StoreAsync("b.example", "beta", Row("192.0.2.16", 5, "fail", "b.example", "fail"));

        var source = await DetailAsync("192.0.2.16", clientSlug: "alpha");

        Assert.Equal(1, source!.DomainCount);
        Assert.Equal("a.example", source.Appearances[0].Domain);
        Assert.False(source.IsCrossClient);
    }
}
