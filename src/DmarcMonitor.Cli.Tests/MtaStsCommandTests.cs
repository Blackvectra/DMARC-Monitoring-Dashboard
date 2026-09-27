using DmarcMonitor.Cli.Commands;
using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Cli.Tests;

/// <summary>
/// <c>dmarc mta-sts set</c> given more than one --mx.
///
/// Its usage text offers <c>[--mx &lt;host&gt;]...</c>, and it reads every --mx
/// it is given, but the argument check refused the second one as a flag given
/// twice and exited 64. A domain with two mail servers could not have them
/// named by hand at all.
/// </summary>
public sealed class MtaStsCommandTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"dmarc-mta-sts-{Guid.NewGuid():N}");
    private string DbPath => Path.Combine(_dir, "dmarc.db");

    public MtaStsCommandTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    [Fact]
    public async Task TheCommandTakesMxMoreThanOnce()
    {
        // There is no database at DbPath, so the command stops at the first
        // thing that needs one. What matters is that it gets that far, rather
        // than being turned away at the argument check.
        var previous = Console.Error;
        using var error = new StringWriter();

        try
        {
            Console.SetError(error);
            var code = await MtaStsCommand.RunAsync(
                ["set", "--domain", "example.org", "--mx", "mx1.example.org", "--mx", "mx2.example.org", "--db", DbPath],
                CancellationToken.None);

            Assert.NotEqual(64, code);
        }
        finally
        {
            Console.SetError(previous);
        }

        Assert.DoesNotContain("more than once", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("is not a DMARC Monitor database", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task EveryMxNamedIsInThePolicy()
    {
        await DatabaseWithExampleOrgAsync();

        var (previousOut, previousError) = (Console.Out, Console.Error);
        using var output = new StringWriter();
        using var error = new StringWriter();

        try
        {
            Console.SetOut(output);
            Console.SetError(error);

            // The second as it might be copied out of a zone file. It is
            // stored the way an MX lookup gives a host name - lower case, no
            // trailing dot - so a server named by hand and the same server
            // taken from DNS are the same string.
            var code = await MtaStsCommand.RunAsync(
                ["set", "--domain", "example.org", "--mx", "mx1.example.org", "--mx", "MX2.Example.org.", "--db", DbPath],
                CancellationToken.None);

            Assert.True(code == 0, error.ToString());
        }
        finally
        {
            Console.SetOut(previousOut);
            Console.SetError(previousError);
        }

        var policy = await new MtaStsStore(DbPath).GetAsync("example.org");
        Assert.NotNull(policy);
        Assert.Equal(["mx1.example.org", "mx2.example.org"], policy.Mx);
    }

    /// <summary>
    /// A database with example.org on file. A policy is stored against a
    /// domain the database knows, and a report is how a domain gets there.
    /// </summary>
    private async Task DatabaseWithExampleOrgAsync()
    {
        var store = new ReportStore(DbPath);
        await store.InitializeAsync(DatabaseSchema.Sql);

        const string xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>receiver.example</org_name>
                <report_id>mta-sts-command</report_id>
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
            """;

        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await store.SaveAggregateAsync(parsed.Report!, xml);
    }
}
