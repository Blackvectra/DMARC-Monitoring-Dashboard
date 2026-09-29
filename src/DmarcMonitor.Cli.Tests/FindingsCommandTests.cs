using System.Text;
using DmarcMonitor.Cli.Commands;
using DmarcMonitor.Core.Findings;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Cli.Tests;

/// <summary>
/// <c>dmarc findings observe</c>, the nightly step that works from what is
/// stored, and the record an import leaves for it: a completed import is a
/// collection the reports source can trust.
/// </summary>
public sealed class FindingsCommandTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"dmarc-findings-command-{Guid.NewGuid():N}");
    private readonly string _db;

    public FindingsCommandTests()
    {
        Directory.CreateDirectory(_dir);
        _db = Path.Combine(_dir, "dmarc.db");
        new ReportStore(_db).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    [Fact]
    public async Task ObserveRunsOnAFreshDatabaseAndExitsZero()
    {
        var (code, output, _) = await RunAsync(["observe", "--db", _db]);

        Assert.Equal(0, code);
        Assert.Contains("exception(s) expired", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnImportIsACollectionTheReportsSourceCanTrust()
    {
        var folder = Path.Combine(_dir, "reports");
        Directory.CreateDirectory(folder);
        await File.WriteAllBytesAsync(Path.Combine(folder, "r-1.xml"), Report("r-1"));

        Assert.Equal(0, await ImportCommand.RunAsync(["--from", folder, "--db", _db], CancellationToken.None));

        var (source, health) = Assert.Single(await new FindingSourceRegistry(_db).HealthAsync(null));
        Assert.Equal(FindingSourceIds.Reports, source.Kind);
        Assert.Null(source.ClientId);
        Assert.Equal(SourceHealth.Healthy, health);

        var (code, output, _) = await RunAsync(["observe", "--db", _db]);
        Assert.Equal(0, code);
        Assert.Contains("local: 0 domain(s) quiet", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SomethingOtherThanObserveOrListIsUsage()
    {
        var (code, _, error) = await RunAsync(["frobnicate"]);

        Assert.Equal(64, code);
        Assert.Contains("dmarc findings observe", error, StringComparison.Ordinal);
        Assert.Contains("dmarc findings list", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListSaysNothingIsOpenAndExitsOneOnceACriticalFindingIs()
    {
        var folder = Path.Combine(_dir, "reports");
        Directory.CreateDirectory(folder);
        await File.WriteAllBytesAsync(Path.Combine(folder, "r-1.xml"), Report("r-1"));
        Assert.Equal(0, await ImportCommand.RunAsync(["--from", folder, "--db", _db], CancellationToken.None));

        var (quiet, output, _) = await RunAsync(["list", "--db", _db]);
        Assert.Equal(0, quiet);
        Assert.Contains("Nothing open", output, StringComparison.Ordinal);

        // What the scan would raise for a loosened record, without the scan.
        var (tenantId, clientId, domainId) = await DomainAsync("example.org");
        await new FindingLifecycle(_db).ObserveAsync(new Observation
        {
            TenantId = tenantId, ClientId = clientId, DomainId = domainId,
            SourceId = FindingSourceIds.DnsScan, Type = FindingTypes.DmarcPolicyWeakened, Rule = "policy_loosened",
            Severity = "critical", Title = "DMARC: p=reject → p=none.", DedupKey = "dns:" + domainId + ":dmarc",
        });

        var (open, listed, _) = await RunAsync(["list", "--db", _db]);
        Assert.Equal(1, open);
        Assert.Contains("critical", listed, StringComparison.Ordinal);
        Assert.Contains("example.org", listed, StringComparison.Ordinal);
        Assert.Contains("p=reject → p=none", listed, StringComparison.Ordinal);
        Assert.Contains("1 critical open", listed, StringComparison.Ordinal);

        // Decided benign: out of the queue, and the exit code follows.
        var finding = Assert.Single(await new FindingStore(_db).ListAsync(new FindingFilter()));
        await new FindingLifecycle(_db).SetAnalystStateAsync(finding.Id, AnalystStates.Benign, "tester", "test domain");
        var (decided, after, _) = await RunAsync(["list", "--db", _db]);
        Assert.Equal(0, decided);
        Assert.Contains("Nothing open", after, StringComparison.Ordinal);
        var (everything, all, _) = await RunAsync(["list", "--db", _db, "--all"]);
        Assert.Equal(0, everything);
        Assert.Contains("benign", all, StringComparison.Ordinal);

        var (missing, _, error) = await RunAsync(["list", "--db", _db, "--org", "nobody"]);
        Assert.Equal(65, missing);
        Assert.Contains("no organization 'nobody'", error, StringComparison.Ordinal);
    }

    private async Task<(string TenantId, string ClientId, string DomainId)> DomainAsync(string name)
    {
        await using var db = new SqliteConnection($"Data Source={_db};Pooling=False");
        await db.OpenAsync();
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT tenant_id, client_id, id FROM domains WHERE name = $name";
        command.Parameters.AddWithValue("$name", name);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync(), $"no domain {name}");
        return (reader.GetString(0), reader.GetString(1), reader.GetString(2));
    }

    [Fact]
    public async Task ObserveNeedsADatabaseThatExists()
    {
        var (code, _, error) = await RunAsync(["observe", "--db", Path.Combine(_dir, "missing.db")]);

        Assert.Equal(66, code);
        Assert.Contains("No database at", error, StringComparison.Ordinal);
    }

    private static async Task<(int Code, string Output, string Error)> RunAsync(string[] args)
    {
        var previousOut = Console.Out;
        var previousError = Console.Error;
        var output = new StringWriter();
        var error = new StringWriter();
        try
        {
            Console.SetOut(output);
            Console.SetError(error);
            var code = await FindingsCommand.RunAsync(args, CancellationToken.None);
            return (code, output.ToString(), error.ToString());
        }
        finally
        {
            Console.SetOut(previousOut);
            Console.SetError(previousError);
        }
    }

    /// <summary>A made-up aggregate report for a domain kept for examples.</summary>
    private static byte[] Report(string reportId) => Encoding.UTF8.GetBytes($"""
        <?xml version="1.0" encoding="UTF-8"?>
        <feedback>
          <report_metadata>
            <org_name>receiver.example</org_name>
            <report_id>{reportId}</report_id>
            <date_range><begin>1757894400</begin><end>1757980799</end></date_range>
          </report_metadata>
          <policy_published><domain>example.org</domain><p>none</p><pct>100</pct></policy_published>
          <record>
            <row><source_ip>192.0.2.25</source_ip><count>5</count>
              <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
            <identifiers><header_from>example.org</header_from></identifiers>
            <auth_results><dkim><domain>example.org</domain><result>pass</result></dkim><spf><domain>example.org</domain><result>pass</result></spf></auth_results>
          </record>
        </feedback>
        """);
}
