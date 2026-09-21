using DmarcMonitor.Cli.Commands;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Cli.Tests;

/// <summary>
/// Auto-assign against more than one organization.
///
/// Every organization carries its own Unassigned client, filed under that
/// same slug, so slugs repeat across organizations. Auto-assign built a
/// dictionary keyed on slug alone and threw on the second one, which took the
/// whole command out the moment a second organization existed - the exact
/// arrangement this product is built for.
/// </summary>
public sealed class AutoAssignTests : IDisposable
{
    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), $"dmarc-autoassign-{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    private async Task TwoOrganizationsEachWithAnUnassignedDomainAsync()
    {
        await new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql);

        // A report for a domain nobody has onboarded is filed under that
        // organization's own Unassigned, which is what brings the second one
        // into being. Two organizations, two clients both slugged
        // 'unassigned'.
        var nrg = new ReportStore(_dbPath, "local");
        var nls = new ReportStore(_dbPath, "nextlayersec");
        await nrg.SaveAggregateAsync(Report("acme.com"), "a", null);
        await nls.SaveAggregateAsync(Report("cornerpost.example"), "b", null);

        Assert.Equal(2, (await nrg.GetClientsAsync())
            .Count(c => c.Slug == ReportStore.UnassignedClientSlug));
    }

    private static DmarcMonitor.Core.Aggregate.AggregateReport Report(string domain)
    {
        var begin = DateTimeOffset.UtcNow.AddDays(-2);
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>google.com</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin><end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>{domain}</domain><p>none</p><pct>100</pct></policy_published>
              <record>
                <row><source_ip>192.0.2.25</source_ip><count>5</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
                <identifiers><header_from>{domain}</header_from></identifiers>
                <auth_results><dkim><domain>{domain}</domain><result>pass</result></dkim><spf><domain>{domain}</domain><result>pass</result></spf></auth_results>
              </record>
            </feedback>
            """;

        var parsed = DmarcMonitor.Core.Aggregate.AggregateReportParser.Parse(xml);
        if (!parsed.Success) { throw new InvalidOperationException($"seed report did not parse: {parsed.Error}"); }
        return parsed.Report!;
    }

    [Fact]
    public async Task SurvivesASecondOrganizationsUnassignedClient()
    {
        await TwoOrganizationsEachWithAnUnassignedDomainAsync();

        // A dry run: it reads every client to check for slug collisions,
        // which is where it used to throw, and writes nothing.
        var code = await ClientCommand.RunAsync(["auto-assign", "--db", _dbPath], CancellationToken.None);

        Assert.Equal(0, code);
    }

    [Fact]
    public async Task AppliesAgainstASecondOrganizationToo()
    {
        await TwoOrganizationsEachWithAnUnassignedDomainAsync();

        var code = await ClientCommand.RunAsync(
            ["auto-assign", "--apply", "--db", _dbPath], CancellationToken.None);

        Assert.Equal(0, code);
    }

    [Fact]
    public async Task AMistypedFlagIsRefusedRatherThanIgnored()
    {
        await TwoOrganizationsEachWithAnUnassignedDomainAsync();

        // --aply is not --apply. It used to be ignored, so the operator was
        // shown a dry run and told nothing had been written - which was true,
        // and not what they asked for.
        var code = await ClientCommand.RunAsync(
            ["auto-assign", "--aply", "--db", _dbPath], CancellationToken.None);

        Assert.Equal(64, code);
    }
}
