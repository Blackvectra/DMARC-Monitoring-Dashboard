using System.Net;
using System.Text;
using System.Text.Json;
using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Findings;
using DmarcMonitor.Core.Notifications;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tests.Ingest;
using DmarcMonitor.Core.Tests.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Core.Tests.Notifications;

/// <summary>
/// Sending what the DNS scan found to whoever is listening, once each, in
/// order, to the right organization's receiver and nobody else's.
/// </summary>
public sealed class WebhookNotifierTests : IDisposable
{
    private const string Secret = "notifier-test-secret-0123456789abcdef";
    private const string Receiver = "https://console.example/api/sources/dmarc-monitor/events";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-notify-{Guid.NewGuid():N}.db");
    private readonly InMemorySecretStore _secrets = new();
    private readonly RecordingHandler _http = new();
    private readonly DnsSnapshotStore _dns;

    public WebhookNotifierTests()
    {
        new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
        FileReport("local", "acme.example", "r-1");
        _dns = new DnsSnapshotStore(_dbPath);
    }

    public void Dispose() => SingleDatabase.Delete(_dbPath);

    /// <summary>A domain exists once a report has arrived for it, in whichever organization it was filed under.</summary>
    private void FileReport(string organization, string domain, string reportId)
    {
        var xml = SyntheticReports.AggregateXml(reportId, domain);
        new ReportStore(_dbPath, organization)
            .SaveAggregateAsync(AggregateReportParser.Parse(xml).Report!, xml, $"msg-{reportId}")
            .GetAwaiter().GetResult();
    }

    private static PublishedRecords Reading(string domain, string? dmarc = "v=DMARC1; p=quarantine; rua=mailto:d@msp.example",
        string spf = "v=spf1 include:_spf.mail.example -all") => new()
    {
        Domain = domain,
        SpfRecords = [spf],
        DmarcRecord = dmarc,
        SpfLookups = 2,
    };

    /// <summary>Two readings of a domain, the second weaker: one critical change.</summary>
    private async Task LoosenedAsync(string domain = "acme.example")
    {
        await _dns.SaveAsync(domain, Reading(domain));
        await _dns.SaveAsync(domain, Reading(domain, dmarc: "v=DMARC1; p=none; rua=mailto:d@msp.example"));
    }

    /// <summary>A destination on the older contract unless the test says otherwise: those tests are about that contract.</summary>
    private Task<Webhook> WebhookAsync(string org = "local", string minSeverity = "warning", TimeProvider? clock = null, string payload = WebhookStore.EventVersion) =>
        new WebhookStore(_dbPath, _secrets, clock).SetAsync(org, Receiver, Secret, minSeverity, "https://dmarc.msp.example/", "tester", payload);

    private WebhookNotifier Notifier(TimeProvider? clock = null) => new(_dbPath, _secrets, _http, clock);

    [Fact]
    public async Task ADestinationSetWithoutSayingGetsTheFindingContract()
    {
        var hook = await new WebhookStore(_dbPath, _secrets).SetAsync("local", Receiver, Secret, "warning", null, "tester");
        Assert.Equal(WebhookStore.FindingVersion, hook.PayloadVersion);
        Assert.True(hook.SendsFindings);

        var older = await WebhookAsync(payload: WebhookStore.EventVersion);
        Assert.Equal(hook.Id, older.Id);
        Assert.False(older.SendsFindings);
        await Assert.ThrowsAsync<ArgumentException>(() => WebhookAsync(payload: "finding.v2"));
    }

    [Fact]
    public async Task AFindingIsSentAsFindingV1WithAPointerAtTheEvidenceAndNoRecordText()
    {
        await WebhookAsync(payload: WebhookStore.FindingVersion);
        await LoosenedAsync();

        var run = Assert.Single(await Notifier().SendAsync());

        Assert.True(run.Worked, run.Error);
        Assert.Equal(1, run.Delivered);
        var sent = Assert.Single(_http.Sent);
        Assert.True(WebhookSigner.Verify(Secret, long.Parse(sent.Timestamp!, System.Globalization.CultureInfo.InvariantCulture), sent.Body, sent.Signature));

        var finding = FindingContract.FromJson(sent.Body)!;
        Assert.Equal(FindingContract.CurrentSchema, finding.Schema);
        Assert.Equal(FindingContract.Version, finding.PayloadVersion);
        Assert.Equal(sent.EventId, finding.Id);
        Assert.Equal(FindingEventKinds.Observed, finding.EventKind);
        Assert.Equal(FindingSourceIds.DnsScan, finding.SourceId);
        Assert.Equal(FindingTypes.DmarcPolicyWeakened, finding.Type);
        Assert.Equal("policy_loosened", finding.Rule);
        Assert.Equal("critical", finding.Severity);
        Assert.Equal("local", finding.Organization.Slug);
        Assert.Equal("acme.example", finding.Domain);
        Assert.StartsWith("dns:", finding.DedupKey, StringComparison.Ordinal);
        Assert.StartsWith("drift:", finding.EvidenceRef, StringComparison.Ordinal);
        Assert.Equal("https://dmarc.msp.example/domains/acme.example", finding.EvidenceLink);
        Assert.Equal(SourceStates.Active, finding.SourceState);
        Assert.Equal(AnalystStates.Unreviewed, finding.AnalystState);
        Assert.Equal(1, finding.ObservationCount);

        // A pointer at the evidence, never the evidence: the record stays in the client's file.
        Assert.DoesNotContain("rua=mailto", sent.Body, StringComparison.Ordinal);
        Assert.Equal(sent.EventId, await ScalarAsync("SELECT event_id FROM webhook_deliveries"));
    }

    [Fact]
    public async Task SeenAgainIsNotSentAgainButWhatChangesOnTheFindingIs()
    {
        await WebhookAsync(payload: WebhookStore.FindingVersion);
        await _dns.SaveAsync("acme.example", Reading("acme.example"));
        await _dns.SaveAsync("acme.example", Reading("acme.example", dmarc: "v=DMARC1; p=quarantine; pct=50; rua=mailto:d@msp.example"));
        Assert.Equal(1, Assert.Single(await Notifier().SendAsync()).Delivered);

        // The same drift another night is the same finding, with nothing new to say.
        await _dns.SaveAsync("acme.example", Reading("acme.example", dmarc: "v=DMARC1; p=quarantine; pct=50; rua=mailto:d@msp.example"));
        Assert.Equal(0, Assert.Single(await Notifier().SendAsync()).Delivered);
        Assert.Single(_http.Sent);

        // Worse, then back as it was, then gone again: each a change on the one finding.
        await _dns.SaveAsync("acme.example", Reading("acme.example", dmarc: null));
        await _dns.SaveAsync("acme.example", Reading("acme.example"));
        await _dns.SaveAsync("acme.example", Reading("acme.example", dmarc: null));

        var run = Assert.Single(await Notifier().SendAsync());
        Assert.True(run.Worked, run.Error);
        Assert.Equal(4, run.Delivered);

        var sent = _http.Sent.Skip(1).Select(s => FindingContract.FromJson(s.Body)!).ToList();
        Assert.Equal([FindingEventKinds.SeverityChanged, FindingEventKinds.TypeChanged, FindingEventKinds.SourceResolved, FindingEventKinds.Reopened],
            sent.Select(f => f.EventKind).ToList());
        Assert.Single(sent.Select(f => f.FindingId).Distinct());
        Assert.Equal(FindingContract.FromJson(_http.Sent[0].Body)!.FindingId, sent[0].FindingId);
        Assert.Equal(5, _http.Sent.Select(s => s.EventId).Distinct().Count());
    }

    [Fact]
    public async Task ATestEventForAFindingDestinationIsInTheShapeItWillReceive()
    {
        await WebhookAsync(payload: WebhookStore.FindingVersion);

        var run = await Notifier().PingAsync("local");

        Assert.True(run.Worked, run.Error);
        var ping = FindingContract.FromJson(Assert.Single(_http.Sent).Body)!;
        Assert.Equal(FindingContract.CurrentSchema, ping.Schema);
        Assert.Equal(FindingContract.PingType, ping.Type);
        Assert.Equal("local", ping.Organization.Slug);
        Assert.Equal("ping", ping.FindingId);
    }

    [Fact]
    public async Task ANewChangeIsSentSignedWithWhatAReceiverNeeds()
    {
        await WebhookAsync();
        await LoosenedAsync();

        var run = Assert.Single(await Notifier().SendAsync());

        Assert.True(run.Worked);
        Assert.Equal(1, run.Delivered);
        var sent = Assert.Single(_http.Sent);
        Assert.Equal(Receiver, sent.Url);

        // The signature is over the exact bytes that arrived, with the
        // timestamp that arrived beside them.
        Assert.True(WebhookSigner.Verify(Secret, long.Parse(sent.Timestamp!, System.Globalization.CultureInfo.InvariantCulture), sent.Body, sent.Signature));

        var evt = WebhookEvent.FromJson(sent.Body)!;
        Assert.Equal(WebhookEvent.CurrentSchema, evt.Schema);
        Assert.Equal(WebhookEvent.DnsDriftType, evt.Type);
        Assert.Equal(sent.EventId, evt.Id);
        Assert.Equal("local", evt.Organization.Slug);
        Assert.Equal("acme.example", evt.Domain);
        Assert.NotNull(evt.Client);
        Assert.Equal("critical", evt.Severity);
        Assert.False(evt.WasExpected);
        Assert.Equal("dmarc", evt.DnsDrift!.RecordType);
        Assert.Contains("p=quarantine", evt.DnsDrift.OldValue, StringComparison.Ordinal);
        Assert.Contains("p=none", evt.DnsDrift.NewValue, StringComparison.Ordinal);
        Assert.Contains("p=quarantine → p=none", evt.Summary, StringComparison.Ordinal);
        Assert.Equal("https://dmarc.msp.example/domains/acme.example", evt.Link);
    }

    [Fact]
    public async Task NothingIsSentTwice()
    {
        await WebhookAsync();
        await LoosenedAsync();

        await Notifier().SendAsync();
        var again = Assert.Single(await Notifier().SendAsync());

        Assert.Equal(0, again.Delivered);
        Assert.Single(_http.Sent);
    }

    /// <summary>Setting a webhook up is not a request for every change the product has ever seen.</summary>
    [Fact]
    public async Task ChangesFromBeforeTheWebhookAreNotSent()
    {
        await LoosenedAsync();
        await WebhookAsync(clock: new Shifted(TimeSpan.FromMinutes(5)));

        var run = Assert.Single(await Notifier(new Shifted(TimeSpan.FromMinutes(5))).SendAsync());

        Assert.Equal(0, run.Delivered);
        Assert.Empty(_http.Sent);
    }

    [Fact]
    public async Task BelowTheChosenSeverityIsNotSent()
    {
        await WebhookAsync(minSeverity: "warning");
        await _dns.SaveAsync("acme.example", Reading("acme.example"));
        await _dns.SaveAsync("acme.example", Reading("acme.example", spf: "v=spf1 include:_spf.mail.example include:send.example -all"));

        Assert.Equal(0, Assert.Single(await Notifier().SendAsync()).Delivered);

        await WebhookAsync(minSeverity: "info");
        Assert.Equal(1, Assert.Single(await Notifier().SendAsync()).Delivered);
        Assert.Equal("info", WebhookEvent.FromJson(Assert.Single(_http.Sent).Body)!.Severity);
    }

    /// <summary>
    /// A receiver that is down fails the run at the first event, keeps it for
    /// next time, and gets it first when it is back - so a domain's changes
    /// arrive in the order they happened.
    /// </summary>
    [Fact]
    public async Task AFailureStopsTheRunAndIsTriedFirstNextTime()
    {
        await WebhookAsync();
        await LoosenedAsync();
        await _dns.SaveAsync("acme.example", Reading("acme.example", dmarc: "v=DMARC1; p=none"));   // and the reports taken away

        _http.Answer = HttpStatusCode.ServiceUnavailable;
        var down = Assert.Single(await Notifier().SendAsync());

        Assert.False(down.Worked);
        Assert.Equal(1, down.Failed);
        Assert.Equal(2, down.Waiting);
        Assert.Contains("503", down.Error, StringComparison.Ordinal);
        Assert.Single(_http.Sent);
        Assert.True((await new WebhookStore(_dbPath, _secrets).GetAsync("local"))!.IsFailing);

        var failedFirst = _http.Sent[0].EventId;
        _http.Answer = HttpStatusCode.Accepted;
        var back = Assert.Single(await Notifier().SendAsync());

        Assert.True(back.Worked);
        Assert.Equal(2, back.Delivered);
        Assert.Equal(failedFirst, _http.Sent[1].EventId);
        Assert.False((await new WebhookStore(_dbPath, _secrets).GetAsync("local"))!.IsFailing);
        Assert.Equal(2L, await ScalarAsync($"SELECT attempts FROM webhook_deliveries WHERE event_id = '{failedFirst}'"));
    }

    /// <summary>A secrets folder not copied with the database is named as the cause, not left to look like a 401.</summary>
    [Fact]
    public async Task AMissingKeyIsSaidPlainlyAndNothingIsSent()
    {
        var hook = await WebhookAsync();
        await LoosenedAsync();
        await _secrets.RemoveAsync(hook.CredentialRef);

        var run = Assert.Single(await Notifier().SendAsync());

        Assert.False(run.Worked);
        Assert.Contains("secret store", run.Error, StringComparison.Ordinal);
        Assert.Empty(_http.Sent);
    }

    [Fact]
    public async Task AfterTwoWeeksAChangeIsHistoryNotNews()
    {
        await WebhookAsync();
        await LoosenedAsync();

        var run = Assert.Single(await Notifier(new Shifted(TimeSpan.FromDays(15))).SendAsync());

        Assert.Equal(0, run.Delivered);
        Assert.Empty(_http.Sent);
    }

    /// <summary>
    /// Two MSPs on one install are competitors. One's receiver must never
    /// hear about the other's clients, and each must hear about its own.
    /// </summary>
    [Fact]
    public async Task EachOrganizationHearsOnlyAboutItsOwnClients()
    {
        FileReport("rival", "rival-client.example", "r-2");
        await WebhookAsync("local");
        await new WebhookStore(_dbPath, _secrets).SetAsync("rival", "https://rival.example/hook", Secret, "warning", null, "tester", WebhookStore.EventVersion);
        await LoosenedAsync("acme.example");
        await LoosenedAsync("rival-client.example");

        var runs = await Notifier().SendAsync();

        Assert.Equal(2, runs.Count);
        var toLocal = Assert.Single(_http.Sent, s => s.Url == Receiver);
        var toRival = Assert.Single(_http.Sent, s => s.Url == "https://rival.example/hook");
        Assert.Equal("acme.example", WebhookEvent.FromJson(toLocal.Body)!.Domain);
        Assert.Equal("rival-client.example", WebhookEvent.FromJson(toRival.Body)!.Domain);
        Assert.Equal("rival", WebhookEvent.FromJson(toRival.Body)!.Organization.Slug);
    }

    [Fact]
    public async Task ATestEventProvesTheReceiverBeforeThereIsAnythingToSend()
    {
        await WebhookAsync();

        var run = await Notifier().PingAsync("local");

        Assert.True(run.Worked);
        var sent = Assert.Single(_http.Sent);
        Assert.Equal(WebhookEvent.PingType, WebhookEvent.FromJson(sent.Body)!.Type);
        Assert.DoesNotContain("wasExpected", sent.Body, StringComparison.Ordinal);
        Assert.True(WebhookSigner.Verify(Secret, long.Parse(sent.Timestamp!, System.Globalization.CultureInfo.InvariantCulture), sent.Body, sent.Signature));
        Assert.NotNull((await new WebhookStore(_dbPath, _secrets).GetAsync("local"))!.LastDeliveredAt);
    }

    [Fact]
    public async Task NoWebhooksIsNothingToDoRatherThanAFailure()
    {
        await LoosenedAsync();

        Assert.Empty(await Notifier().SendAsync());
        Assert.Empty(_http.Sent);
    }

    private async Task<object?> ScalarAsync(string sql)
    {
        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _dbPath, Pooling = false }.ToString());
        await db.OpenAsync();
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteScalarAsync();
    }

    private sealed record Sent(string Url, string Body, string? Timestamp, string? Signature, string? EventId);

    /// <summary>Answers every request the same way, and keeps what was sent - read before the request is disposed.</summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<Sent> Sent { get; } = [];
        public HttpStatusCode Answer { get; set; } = HttpStatusCode.OK;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string? Header(string name) => request.Headers.TryGetValues(name, out var values) ? values.Single() : null;

            Sent.Add(new Sent(
                request.RequestUri!.ToString(),
                await request.Content!.ReadAsStringAsync(cancellationToken),
                Header(WebhookSigner.TimestampHeader),
                Header(WebhookSigner.SignatureHeader),
                Header(WebhookSigner.EventIdHeader)));

            return new HttpResponseMessage(Answer)
            {
                Content = new StringContent(Answer == HttpStatusCode.OK ? "{}" : "receiver is restarting", Encoding.UTF8, "text/plain"),
            };
        }
    }

    private sealed class Shifted(TimeSpan by) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => base.GetUtcNow() + by;
    }
}
