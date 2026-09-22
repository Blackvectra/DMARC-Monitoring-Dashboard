using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// Filing domains under clients without being asked to, at import.
///
/// An import of a real mailbox arrives with seventeen domains in it and, left
/// alone, files all seventeen under Unassigned - so somebody creates
/// seventeen clients by hand and assigns seventeen domains to reach the
/// grouping the import already knew. The domain IS the grouping until a person
/// says otherwise.
///
/// Most of what is below is about the two ways that goes wrong: filing two
/// different customers together, and inventing a name for one of them.
/// </summary>
public sealed class ClientFilerTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-filing-{Guid.NewGuid():N}.db");
    private readonly ReportStore _store;

    public ClientFilerTests()
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

    /// <summary>Stores one report for a domain, which is how a domain comes to exist.</summary>
    private async Task SeenAsync(string domain)
    {
        var begin = DateTimeOffset.UtcNow.AddDays(-1);
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata><org_name>google.com</org_name><report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin>
                            <end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range></report_metadata>
              <policy_published><domain>{domain}</domain><p>none</p><pct>100</pct></policy_published>
              <record>
                <row><source_ip>192.0.2.10</source_ip><count>5</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
                <identifiers><header_from>{domain}</header_from></identifiers>
                <auth_results><dkim><domain>{domain}</domain><result>pass</result></dkim>
                  <spf><domain>{domain}</domain><result>pass</result></spf></auth_results>
              </record>
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await _store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

    private async Task<string> ClientOfAsync(string domain)
    {
        var domains = await _store.GetDomainsAsync();
        return domains.First(d => d.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase)).ClientSlug;
    }

    [Fact]
    public async Task ADomainNobodyFiledGetsAClientOfItsOwn()
    {
        await SeenAsync("acme.example");

        var result = await ClientFiler.ApplyAsync(_store);

        Assert.Equal(1, result.NewClients);
        Assert.Equal("acme-example", await ClientOfAsync("acme.example"));

        // Named after the domain rather than a guess at the business. Deriving
        // "Acme" from acme.example reads as confident and is the one thing
        // that must not be guessed: it goes on the customer's report.
        var clients = await _store.GetClientsAsync();
        Assert.Contains(clients, c => c.Name == "acme.example");
    }

    /// <summary>
    /// A subdomain joins its parent rather than becoming a second customer.
    /// </summary>
    /// <remarks>
    /// The parent is looked for among domains this install already has, not
    /// worked out from the name, which sidesteps the public suffix list
    /// entirely: there is no table of co.uk to keep current and no chance of
    /// filing two unrelated customers together because a suffix was missing
    /// from it.
    /// </remarks>
    [Fact]
    public async Task ASubdomainJoinsItsParentsClient()
    {
        await SeenAsync("acme.example");
        await SeenAsync("mail.acme.example");
        await SeenAsync("eu.mail.acme.example");

        var result = await ClientFiler.ApplyAsync(_store);

        // One client, three domains.
        Assert.Equal(1, result.NewClients);
        Assert.Equal(3, result.Filed.Count);
        Assert.Equal("acme-example", await ClientOfAsync("mail.acme.example"));
        Assert.Equal("acme-example", await ClientOfAsync("eu.mail.acme.example"));
    }

    /// <summary>
    /// Two domains under the same public suffix are not related, and nothing
    /// here may decide that they are.
    /// </summary>
    [Fact]
    public async Task TwoDomainsSharingASuffixStayApart()
    {
        await SeenAsync("acme.example");
        await SeenAsync("notacme.example");

        var result = await ClientFiler.ApplyAsync(_store);

        Assert.Equal(2, result.NewClients);
        Assert.NotEqual(await ClientOfAsync("acme.example"), await ClientOfAsync("notacme.example"));
    }

    /// <summary>
    /// A domain whose slug is already somebody else's is left alone and the
    /// reason is carried back.
    /// </summary>
    /// <remarks>
    /// Filing two customers together is not a thing to discover from a
    /// client's report, and the slug is permanent because it goes into report
    /// filenames - so this refuses rather than disambiguating with a suffix
    /// nobody chose.
    /// </remarks>
    [Fact]
    public async Task ASlugThatIsTakenIsRefusedRatherThanReused()
    {
        await _store.CreateClientAsync("Somebody Else", "acme-example");
        await SeenAsync("acme.example");

        var result = await ClientFiler.ApplyAsync(_store);

        Assert.Empty(result.Filed);
        var skipped = Assert.Single(result.Skipped);
        Assert.Contains("already", skipped.Skipped, StringComparison.Ordinal);
        Assert.Equal(ReportStore.UnassignedClientSlug, await ClientOfAsync("acme.example"));
    }

    [Fact]
    public async Task PlanningWritesNothing()
    {
        await SeenAsync("acme.example");

        var plan = await ClientFiler.PlanAsync(_store);

        Assert.Single(plan.Filed);
        Assert.Equal(ReportStore.UnassignedClientSlug, await ClientOfAsync("acme.example"));
        Assert.DoesNotContain(await _store.GetClientsAsync(), c => c.Slug == "acme-example");
    }

    [Fact]
    public async Task ADomainSomebodyAlreadyFiledIsLeftWhereItIs()
    {
        await SeenAsync("acme.example");
        await _store.CreateClientAsync("Acme Corporation", "acme-corp");
        await _store.AssignDomainAsync("acme.example", "acme-corp");

        var result = await ClientFiler.ApplyAsync(_store);

        Assert.False(result.DidAnything);
        Assert.Equal("acme-corp", await ClientOfAsync("acme.example"));
    }

    [Fact]
    public async Task RunningItTwiceChangesNothingTheSecondTime()
    {
        await SeenAsync("acme.example");

        var first = await ClientFiler.ApplyAsync(_store);
        var second = await ClientFiler.ApplyAsync(_store);

        Assert.True(first.DidAnything);
        Assert.False(second.DidAnything);
    }

    [Fact]
    public async Task NothingToFileIsNotAnError()
    {
        var result = await ClientFiler.ApplyAsync(_store);

        Assert.False(result.DidAnything);
        Assert.Empty(result.Skipped);
    }

    [Fact]
    public async Task ANullStoreIsRefused()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => ClientFiler.ApplyAsync(null!));
        await Assert.ThrowsAsync<ArgumentNullException>(() => ClientFiler.PlanAsync(null!));
    }
}
