using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tests.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Aggregate;

/// <summary>
/// What a receiver's reason for not applying a policy excuses.
///
/// A receiver wrote "other" beside a message it had quarantined, from a home
/// broadband address, signed with a made-up selector on the victim's domain.
/// The tool called it a forwarder or mailing list and said to ignore it: the
/// rule was "any reason at all". The one query that tried to make an exception
/// spelled it with an underscore the store never writes, and matched nothing.
/// </summary>
public sealed class PolicyOverridesTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-overrides-{Guid.NewGuid():N}.db");
    private readonly ReportStore _store;

    public PolicyOverridesTests()
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

    private static string Reason(string type) => $"<reason><type>{type}</type></reason>";

    private static string Report(params string[] reasons) => $"""
        <?xml version="1.0" encoding="UTF-8"?>
        <feedback>
          <report_metadata>
            <org_name>reporter.example.net</org_name><report_id>{Guid.NewGuid():N}</report_id>
            <date_range><begin>{DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds()}</begin>
                        <end>{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}</end></date_range>
          </report_metadata>
          <policy_published><domain>example.com</domain><p>quarantine</p><pct>100</pct></policy_published>
          <record>
            <row>
              <source_ip>192.0.2.10</source_ip><count>3</count>
              <policy_evaluated>
                <disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf>
                {string.Join("\n    ", reasons)}
              </policy_evaluated>
            </row>
            <identifiers><header_from>example.com</header_from></identifiers>
            <auth_results>
              <dkim><domain>example.com</domain><selector>s1</selector><result>fail</result></dkim>
              <spf><domain>example.com</domain><result>fail</result></spf>
            </auth_results>
          </record>
        </feedback>
        """;

    private static ReportRecord Parse(params string[] reasons)
    {
        var parsed = AggregateReportParser.Parse(Report(reasons));
        Assert.True(parsed.Success, parsed.Error);
        return Assert.Single(parsed.Report!.Records);
    }

    private async Task SaveAsync(params string[] reasons)
    {
        var xml = Report(reasons);
        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await _store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

    /// <summary>What the shared condition says about the one stored row, aliased or not.</summary>
    private async Task<bool> ExcusedAsync(string alias)
    {
        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
        await using var command = connection.CreateCommand();
        var from = alias.Length == 0 ? "aggregate_records" : $"aggregate_records {alias}";
        command.CommandText = $"SELECT {PolicyOverrides.ExcusedSql(alias)} FROM {from}";

        // A null here is a failure of its own: NOT of it is null, and a query
        // that meant to keep the row would drop it.
        var value = await command.ExecuteScalarAsync();
        Assert.NotNull(value);
        Assert.IsNotType<DBNull>(value);
        return Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture) == 1;
    }

    [Theory]
    [InlineData(OverrideReason.Forwarded, true)]
    [InlineData(OverrideReason.TrustedForwarder, true)]
    [InlineData(OverrideReason.MailingList, true)]
    [InlineData(OverrideReason.LocalPolicy, true)]
    [InlineData(OverrideReason.SampledOut, false)]
    [InlineData(OverrideReason.Other, false)]
    [InlineData(OverrideReason.Unknown, false)]
    public void OnlyAReasonThatSaysTheFailureWasExpectedExcusesIt(OverrideReason reason, bool excuses) =>
        Assert.Equal(excuses, PolicyOverrides.Excuses(reason));

    [Theory]
    [InlineData("forwarded", true)]
    [InlineData("trusted_forwarder", true)]
    [InlineData("mailing_list", true)]
    [InlineData("local_policy", true)]
    [InlineData("sampled_out", false)]
    [InlineData("other", false)]
    [InlineData("something_a_receiver_made_up", false)]
    public void ARecordIsOverriddenOnlyWhenItsReasonExcuses(string received, bool overridden) =>
        Assert.Equal(overridden, Parse(Reason(received)).WasOverridden);

    [Fact]
    public void OneReasonThatExcusesIsEnoughWhateverElseIsListed()
    {
        Assert.True(Parse(Reason("other"), Reason("forwarded")).WasOverridden);
        Assert.False(Parse(Reason("other"), Reason("sampled_out")).WasOverridden);
    }

    [Fact]
    public void ARecordWithNoReasonWasNotOverridden() =>
        Assert.False(Parse().WasOverridden);

    /// <summary>
    /// The condition every query uses has to read what the store wrote. This is
    /// the test that would have caught the carve-out for <c>sampled_out</c>
    /// that matched nothing, because the store writes it without the
    /// underscore.
    /// </summary>
    [Theory]
    [InlineData("forwarded", true)]
    [InlineData("trusted_forwarder", true)]
    [InlineData("mailing_list", true)]
    [InlineData("local_policy", true)]
    [InlineData("sampled_out", false)]
    [InlineData("other", false)]
    [InlineData("something_a_receiver_made_up", false)]
    public async Task TheQueriesReadTheReasonTheStoreWrote(string received, bool excused)
    {
        await SaveAsync(Reason(received));

        Assert.Equal(excused, await ExcusedAsync("r"));
    }

    [Fact]
    public async Task TheConditionWorksWithoutAnAlias()
    {
        await SaveAsync(Reason("mailing_list"));

        Assert.True(await ExcusedAsync(""));
    }

    [Fact]
    public async Task AStoredRecordWithSeveralReasonsIsExcusedIfAnyOfThemDoes()
    {
        await SaveAsync(Reason("sampled_out"), Reason("forwarded"));

        Assert.True(await ExcusedAsync("r"));
    }

    [Fact]
    public async Task ARowWithNoReasonIsNotExcusedAndIsNotNull()
    {
        await SaveAsync();

        Assert.False(await ExcusedAsync("r"));
    }
}
