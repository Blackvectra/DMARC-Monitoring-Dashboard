using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Findings;
using DmarcMonitor.Core.Notifications;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;
using DmarcMonitor.Core.Tests.Ingest;
using DmarcMonitor.Core.Tests.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Core.Tests.Notifications;

/// <summary>
/// Filing what the DNS scan found as ConnectWise tickets: one per finding on
/// the right client's company, a note while a tech has it open, and never a
/// ticket for a client nobody has mapped.
/// </summary>
/// <remarks>
/// Against a fake ConnectWise that checks the credential the way the real one
/// does and keeps what was filed. There is no public ConnectWise sandbox, so
/// the real instance is proved by <c>dmarc notify test</c> on the day.
/// </remarks>
public sealed class ConnectWiseNotifierTests : IDisposable
{
    private const string Site = "https://cw.example";
    private const string CompanyId = "NRGTS";
    private const string PublicKey = "PublicKeyAbc123";
    private const string PrivateKey = "PrivateKeySecret987";
    private const string ClientId = "11111111-2222-3333-4444-555555555555";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-cw-{Guid.NewGuid():N}.db");
    private readonly InMemorySecretStore _secrets = new();
    private readonly FakeConnectWise _cw = new();
    private readonly DnsSnapshotStore _dns;

    public ConnectWiseNotifierTests()
    {
        new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
        Onboard("local", "acme.example", "r-1", "Acme Corp");
        _dns = new DnsSnapshotStore(_dbPath);
        _cw.ExpectedAuthorization = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{CompanyId}+{PublicKey}:{PrivateKey}"));
        _cw.ExpectedClientId = ClientId;
    }

    public void Dispose() => SingleDatabase.Delete(_dbPath);

    /// <summary>A report files the domain; a client is made and the domain filed under it.</summary>
    private string Onboard(string organization, string domain, string reportId, string clientName)
    {
        var xml = SyntheticReports.AggregateXml(reportId, domain);
        var store = new ReportStore(_dbPath, organization);
        store.SaveAggregateAsync(AggregateReportParser.Parse(xml).Report!, xml, $"msg-{reportId}").GetAwaiter().GetResult();
        var slug = store.CreateClientAsync(clientName).GetAwaiter().GetResult()!;
        store.AssignDomainAsync(domain, slug).GetAwaiter().GetResult();
        return slug;
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
    private Task<Webhook> ConnectWiseAsync(string org = "local", string minSeverity = "warning", string board = "Alerts", string payload = WebhookStore.EventVersion) =>
        new WebhookStore(_dbPath, _secrets).SetConnectWiseAsync(org, Site, CompanyId, PublicKey, PrivateKey, ClientId,
            new ConnectWiseSettings(board, "New", "Priority 1 - Emergency", "Priority 3 - Medium"),
            minSeverity, "https://dmarc.msp.example/", "tester", payload);

    [Fact]
    public async Task AFindingIsOneTicketHoweverManyNightsSeeIt()
    {
        await ConnectWiseAsync(payload: WebhookStore.FindingVersion);
        await MapAsync("acme-corp", 1001);
        await LoosenedAsync();
        Assert.Equal(1, Assert.Single(await Notifier().SendAsync()).Delivered);

        // Two more nights of the same drift: the same finding, nothing to file.
        await _dns.SaveAsync("acme.example", Reading("acme.example", dmarc: "v=DMARC1; p=none; rua=mailto:d@msp.example"));
        await _dns.SaveAsync("acme.example", Reading("acme.example", dmarc: "v=DMARC1; p=none; rua=mailto:d@msp.example"));
        Assert.Equal(0, Assert.Single(await Notifier().SendAsync()).Delivered);

        var ticket = Assert.Single(_cw.Tickets.Values);
        Assert.Empty(_cw.Notes);
        Assert.Equal(1001, ticket.CompanyId);
        Assert.Equal("Priority 1 - Emergency", ticket.Priority);
        Assert.StartsWith("DMARC: Acme Corp: ", ticket.Summary, StringComparison.Ordinal);
        Assert.Contains("p=quarantine → p=none", ticket.Summary, StringComparison.Ordinal);
        Assert.Matches(@" \[dm:[0-9a-f]{8}\]$", ticket.Summary);
        Assert.Contains("Was: v=DMARC1; p=quarantine", ticket.Description, StringComparison.Ordinal);
        Assert.Contains("Now: v=DMARC1; p=none", ticket.Description, StringComparison.Ordinal);
        Assert.Contains("https://dmarc.msp.example/domains/acme.example", ticket.Description, StringComparison.Ordinal);

        // The ledger keys the ticket to the finding, and the finding's history names the ticket.
        var findings = new FindingStore(_dbPath);
        var finding = Assert.Single(await findings.ListAsync(new FindingFilter()));
        Assert.Contains("finding " + finding.Id, ticket.Description, StringComparison.Ordinal);
        Assert.Equal(finding.Id, await ScalarAsync("SELECT remote_key FROM webhook_deliveries"));
        Assert.Equal(ticket.Id.ToString(CultureInfo.InvariantCulture), await ScalarAsync("SELECT remote_id FROM webhook_deliveries"));
        var filed = Assert.Single(await findings.EventsAsync(finding.Id), e => e.Kind == FindingEventKinds.TicketCreated);
        Assert.Equal(ticket.Id.ToString(CultureInfo.InvariantCulture), filed.ToValue);
        Assert.Contains("'Alerts'", filed.Note, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WhatChangesOnTheFindingIsANoteWhileTheTicketIsOpen()
    {
        await ConnectWiseAsync(payload: WebhookStore.FindingVersion);
        await MapAsync("acme-corp", 1001);
        await _dns.SaveAsync("acme.example", Reading("acme.example"));
        await _dns.SaveAsync("acme.example", Reading("acme.example", dmarc: "v=DMARC1; p=quarantine; pct=50; rua=mailto:d@msp.example"));
        await Notifier().SendAsync();
        var ticket = Assert.Single(_cw.Tickets.Values);
        Assert.Equal("Priority 3 - Medium", ticket.Priority);

        // Worse, then back as it was: notes on the ticket the tech has.
        await _dns.SaveAsync("acme.example", Reading("acme.example", dmarc: null));
        await _dns.SaveAsync("acme.example", Reading("acme.example"));
        var run = Assert.Single(await Notifier().SendAsync());

        Assert.True(run.Worked, run.Error);
        Assert.Equal(3, run.Delivered);
        Assert.Single(_cw.Tickets.Values);
        Assert.Equal(3, _cw.Notes.Count);
        Assert.All(_cw.Notes, note => Assert.Equal(ticket.Id, note.Ticket));
        Assert.StartsWith("Severity warning → critical", _cw.Notes[0].Text, StringComparison.Ordinal);
        Assert.Contains("Now: (not published)", _cw.Notes[0].Text, StringComparison.Ordinal);
        Assert.StartsWith("Now " + FindingTypes.DmarcPolicyWeakened, _cw.Notes[1].Text, StringComparison.Ordinal);
        Assert.StartsWith("Resolved by its source", _cw.Notes[2].Text, StringComparison.Ordinal);
        Assert.Contains("Close this ticket", _cw.Notes[2].Text, StringComparison.Ordinal);

        // What a person decides here reaches the tech there.
        var findings = new FindingStore(_dbPath);
        var finding = Assert.Single(await findings.ListAsync(new FindingFilter()));
        await new FindingLifecycle(_dbPath).AcknowledgeAsync(finding.Id, "tech@msp.example", "looking");
        Assert.Equal(1, Assert.Single(await Notifier().SendAsync()).Delivered);
        Assert.StartsWith("Acknowledged in DMARC Monitor by tech@msp.example", _cw.Notes[3].Text, StringComparison.Ordinal);
        Assert.Contains("looking", _cw.Notes[3].Text, StringComparison.Ordinal);
        Assert.Equal(4, (await findings.EventsAsync(finding.Id)).Count(e => e.Kind == FindingEventKinds.TicketUpdated));
    }

    [Fact]
    public async Task AFindingBackAfterItsTicketWasClosedGetsANewTicketNamingTheOld()
    {
        await ConnectWiseAsync(payload: WebhookStore.FindingVersion);
        await MapAsync("acme-corp", 1001);
        await LoosenedAsync();
        await Notifier().SendAsync();
        var first = Assert.Single(_cw.Tickets.Values);
        first.Closed = true;

        // Resolved after the tech closed it: nothing a closed ticket needs to hear, and delivered.
        await _dns.SaveAsync("acme.example", Reading("acme.example"));
        Assert.Equal(1, Assert.Single(await Notifier().SendAsync()).Delivered);
        Assert.Single(_cw.Tickets.Values);
        Assert.Empty(_cw.Notes);

        // Back again: a new ticket, naming the old one.
        await _dns.SaveAsync("acme.example", Reading("acme.example", dmarc: "v=DMARC1; p=none; rua=mailto:d@msp.example"));
        Assert.Equal(1, Assert.Single(await Notifier().SendAsync()).Delivered);

        Assert.Equal(2, _cw.Tickets.Count);
        var second = _cw.Tickets.Values.Single(t => t.Id != first.Id);
        Assert.StartsWith($"Previously ticket #{first.Id}, since closed.", second.Description, StringComparison.Ordinal);
        Assert.Contains("Now: v=DMARC1; p=none", second.Description, StringComparison.Ordinal);

        var findings = new FindingStore(_dbPath);
        var finding = Assert.Single(await findings.ListAsync(new FindingFilter()));
        Assert.Equal(2, (await findings.EventsAsync(finding.Id)).Count(e => e.Kind == FindingEventKinds.TicketCreated));
        Assert.Equal(second.Id.ToString(CultureInfo.InvariantCulture), await ScalarAsync("SELECT remote_id FROM webhook_deliveries ORDER BY delivered_at DESC, rowid DESC LIMIT 1"));
    }

    private async Task MapAsync(string clientSlug, int company, string org = "local") =>
        Assert.True(await new ClientSettingsStore(_dbPath).SetAsync(org, clientSlug, ClientSettingsStore.ConnectWiseCompany,
            company.ToString(CultureInfo.InvariantCulture)), $"no client '{clientSlug}' in '{org}'");

    private WebhookNotifier Notifier() => new(_dbPath, _secrets, _cw);

    [Fact]
    public async Task AChangeBecomesATicketOnTheClientsCompanyWithTheCredentialConnectWiseExpects()
    {
        await ConnectWiseAsync();
        await MapAsync("acme-corp", 1001);
        await LoosenedAsync();

        var run = Assert.Single(await Notifier().SendAsync());

        Assert.True(run.Worked, run.Error);
        Assert.Equal(1, run.Delivered);
        Assert.Empty(run.Unmapped);

        // The fake answers 401 to anything but the exact Basic credential and
        // clientId header, so a ticket existing at all proves both.
        var ticket = Assert.Single(_cw.Tickets.Values);
        Assert.Equal("Alerts", ticket.Board);
        Assert.Equal(1001, ticket.CompanyId);
        Assert.Equal("New", ticket.Status);
        Assert.Equal("Priority 1 - Emergency", ticket.Priority);
        Assert.StartsWith("DMARC: Acme Corp: ", ticket.Summary, StringComparison.Ordinal);
        Assert.Contains("p=quarantine → p=none", ticket.Summary, StringComparison.Ordinal);
        Assert.Matches(@" \[dm:[0-9a-f]{8}\]$", ticket.Summary);
        Assert.True(ticket.Summary.Length <= ConnectWiseClient.SummaryLimit);
        Assert.Contains("acme.example", ticket.Description, StringComparison.Ordinal);
        Assert.Contains("Was: v=DMARC1; p=quarantine", ticket.Description, StringComparison.Ordinal);
        Assert.Contains("Now: v=DMARC1; p=none", ticket.Description, StringComparison.Ordinal);
        Assert.Contains("https://dmarc.msp.example/domains/acme.example", ticket.Description, StringComparison.Ordinal);

        // The ledger knows which ticket the finding is on, so a repeat can find it.
        Assert.Equal(ticket.Id.ToString(CultureInfo.InvariantCulture), await ScalarAsync("SELECT remote_id FROM webhook_deliveries"));
        Assert.StartsWith("dns.drift:", (string)(await ScalarAsync("SELECT remote_key FROM webhook_deliveries"))!, StringComparison.Ordinal);
        Assert.NotNull((await new WebhookStore(_dbPath, _secrets).GetAsync("local", WebhookStore.ConnectWiseKind))!.LastDeliveredAt);
    }

    [Fact]
    public async Task ARepeatWhileTheTicketIsOpenIsANoteNotASecondTicket()
    {
        await ConnectWiseAsync();
        await MapAsync("acme-corp", 1001);
        await LoosenedAsync();
        await Notifier().SendAsync();

        // The same record changes again: the same finding, a tech still has it.
        await _dns.SaveAsync("acme.example", Reading("acme.example", dmarc: "v=DMARC1; p=none"));
        var run = Assert.Single(await Notifier().SendAsync());

        Assert.Equal(1, run.Delivered);
        var ticket = Assert.Single(_cw.Tickets.Values);
        var note = Assert.Single(_cw.Notes);
        Assert.Equal(ticket.Id, note.Ticket);
        Assert.StartsWith("Seen again", note.Text, StringComparison.Ordinal);
        Assert.Contains("Now: v=DMARC1; p=none", note.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OnceATechClosedTheTicketTheNextChangeOpensANewOneNamingTheOld()
    {
        await ConnectWiseAsync();
        await MapAsync("acme-corp", 1001);
        await LoosenedAsync();
        await Notifier().SendAsync();
        var first = Assert.Single(_cw.Tickets.Values);
        first.Closed = true;

        await _dns.SaveAsync("acme.example", Reading("acme.example", dmarc: "v=DMARC1; p=none"));
        await Notifier().SendAsync();

        Assert.Equal(2, _cw.Tickets.Count);
        Assert.Empty(_cw.Notes);
        var second = _cw.Tickets.Values.Single(t => t.Id != first.Id);
        Assert.StartsWith($"Previously ticket #{first.Id}, since closed.", second.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// A client nobody has mapped must not hold every other client's tickets,
    /// and must not be filed on a guessed company either. Its events wait,
    /// the run names it, and they go once it is mapped.
    /// </summary>
    [Fact]
    public async Task AClientWithNoCompanyIsNamedAndWaitsWithoutStoppingTheOthers()
    {
        Onboard("local", "globex.example", "r-2", "Globex");
        await ConnectWiseAsync();
        await MapAsync("acme-corp", 1001);
        await LoosenedAsync("acme.example");
        await LoosenedAsync("globex.example");

        var run = Assert.Single(await Notifier().SendAsync());

        Assert.True(run.Worked, run.Error);
        Assert.Equal(1, run.Delivered);
        Assert.Equal(1, run.Waiting);
        Assert.Equal(["globex"], run.Unmapped);
        Assert.Equal(1001, Assert.Single(_cw.Tickets.Values).CompanyId);

        await MapAsync("globex", 1002);
        var again = Assert.Single(await Notifier().SendAsync());

        Assert.Equal(1, again.Delivered);
        Assert.Empty(again.Unmapped);
        Assert.Contains(_cw.Tickets.Values, t => t.CompanyId == 1002 && t.Summary.Contains("Globex", StringComparison.Ordinal));
    }

    /// <summary>
    /// ConnectWise created the ticket and the answer never came back. The next
    /// run finds it by the marker in its summary rather than filing it again.
    /// </summary>
    [Fact]
    public async Task ACreateWhoseAnswerWasLostIsFoundAgainRatherThanFiledTwice()
    {
        await ConnectWiseAsync();
        await MapAsync("acme-corp", 1001);
        await LoosenedAsync();

        _cw.LoseNextCreateAnswer = true;
        var lost = Assert.Single(await Notifier().SendAsync());
        Assert.False(lost.Worked);
        Assert.Contains("502", lost.Error, StringComparison.Ordinal);
        Assert.Single(_cw.Tickets);

        var recovered = Assert.Single(await Notifier().SendAsync());

        Assert.True(recovered.Worked, recovered.Error);
        Assert.Equal(1, recovered.Delivered);
        var ticket = Assert.Single(_cw.Tickets.Values);
        Assert.Equal(ticket.Id.ToString(CultureInfo.InvariantCulture), await ScalarAsync("SELECT remote_id FROM webhook_deliveries"));
    }

    [Fact]
    public async Task AFailureStopsTheRunAndIsTriedFirstNextTime()
    {
        await ConnectWiseAsync();
        await MapAsync("acme-corp", 1001);
        await LoosenedAsync();
        await _dns.SaveAsync("acme.example", Reading("acme.example", dmarc: "v=DMARC1; p=none"));

        _cw.Fail = HttpStatusCode.ServiceUnavailable;
        var down = Assert.Single(await Notifier().SendAsync());

        Assert.False(down.Worked);
        Assert.Equal(1, down.Failed);
        Assert.Equal(2, down.Waiting);
        Assert.Contains("503", down.Error, StringComparison.Ordinal);
        Assert.Empty(_cw.Tickets);
        Assert.True((await new WebhookStore(_dbPath, _secrets).GetAsync("local", WebhookStore.ConnectWiseKind))!.IsFailing);

        _cw.Fail = null;
        var back = Assert.Single(await Notifier().SendAsync());

        Assert.True(back.Worked, back.Error);
        Assert.Equal(2, back.Delivered);
        Assert.Single(_cw.Tickets);   // the second change is a note on the first
        Assert.Single(_cw.Notes);
    }

    [Fact]
    public async Task AWrongKeyIsSaidInConnectWisesWordsAndNothingIsFiled()
    {
        await ConnectWiseAsync();
        await MapAsync("acme-corp", 1001);
        await LoosenedAsync();
        _cw.ExpectedClientId = "some-other-integration";

        var run = Assert.Single(await Notifier().SendAsync());

        Assert.False(run.Worked);
        Assert.Contains("401", run.Error, StringComparison.Ordinal);
        Assert.Contains("clientId", run.Error, StringComparison.Ordinal);
        Assert.Empty(_cw.Tickets);
    }

    [Fact]
    public async Task ThePriorityFollowsTheSeverity()
    {
        await ConnectWiseAsync();
        await MapAsync("acme-corp", 1001);
        await _dns.SaveAsync("acme.example", Reading("acme.example"));
        await _dns.SaveAsync("acme.example", Reading("acme.example", spf: "v=spf1 include:_spf.mail.example ~all"));   // a warning

        await Notifier().SendAsync();

        Assert.Equal("Priority 3 - Medium", Assert.Single(_cw.Tickets.Values).Priority);
    }

    [Fact]
    public async Task AWebhookAndConnectWiseBothHearTheSameChange()
    {
        var webhook = new RecordingWebhook();
        var both = new Router(_cw, webhook);
        await new WebhookStore(_dbPath, _secrets).SetAsync("local", "https://console.example/hook", "notifier-test-secret-0123456789abcdef", "warning", null, "tester");
        await ConnectWiseAsync();
        await MapAsync("acme-corp", 1001);
        await LoosenedAsync();

        var runs = await new WebhookNotifier(_dbPath, _secrets, both).SendAsync();

        Assert.Equal(2, runs.Count);
        Assert.All(runs, r => Assert.True(r.Worked, r.Error));
        Assert.Equal(1, webhook.Posts);
        Assert.Single(_cw.Tickets);
    }

    [Fact]
    public async Task TheTestSignsInFindsTheBoardAndCanFileATestTicket()
    {
        await ConnectWiseAsync();
        await MapAsync("acme-corp", 1001);

        var signIn = await Notifier().TestConnectWiseAsync("local");
        Assert.True(signIn.Worked, signIn.Message);
        Assert.Contains("board 'Alerts' found", signIn.Message, StringComparison.Ordinal);
        Assert.Empty(_cw.Tickets);

        var filed = await Notifier().TestConnectWiseAsync("local", "acme-corp");
        Assert.True(filed.Worked, filed.Message);
        var ticket = Assert.Single(_cw.Tickets.Values);
        Assert.Contains($"#{ticket.Id}", filed.Message, StringComparison.Ordinal);
        Assert.Contains("safe to close", ticket.Summary, StringComparison.Ordinal);
        Assert.Equal(1001, ticket.CompanyId);

        var unmapped = await Notifier().TestConnectWiseAsync("local", "nobody");
        Assert.False(unmapped.Worked);

        await ConnectWiseAsync(board: "No Such Board");
        var noBoard = await Notifier().TestConnectWiseAsync("local");
        Assert.False(noBoard.Worked);
        Assert.Contains("no service board called 'No Such Board'", noBoard.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CompaniesAreFoundByPartOfTheirNameForAPersonToPick()
    {
        await ConnectWiseAsync();

        var found = await Notifier().SearchCompaniesAsync("local", "acm");

        var acme = Assert.Single(found);
        Assert.Equal(1001, acme.Id);
        Assert.Equal("ACME", acme.Identifier);
        Assert.Equal("Acme Corp", acme.Name);
    }

    /// <summary>Two organizations on one install: one's ConnectWise never hears about the other's clients.</summary>
    [Fact]
    public async Task AnotherOrganizationsChangesAreNotFiledHere()
    {
        Onboard("rival", "rival-client.example", "r-3", "Rival Client");
        await ConnectWiseAsync();
        await MapAsync("acme-corp", 1001);
        await LoosenedAsync("acme.example");
        await LoosenedAsync("rival-client.example");

        var run = Assert.Single(await Notifier().SendAsync());

        Assert.Equal(1, run.Delivered);
        Assert.Equal(0, run.Waiting);
        Assert.Contains("Acme Corp", Assert.Single(_cw.Tickets.Values).Summary, StringComparison.Ordinal);
    }

    private async Task<object?> ScalarAsync(string sql)
    {
        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _dbPath, Pooling = false }.ToString());
        await db.OpenAsync();
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteScalarAsync();
    }

    internal sealed class FakeTicket
    {
        public int Id { get; init; }
        public required string Summary { get; init; }
        public required string Board { get; init; }
        public int CompanyId { get; init; }
        public string? Status { get; init; }
        public string? Priority { get; init; }
        public required string Description { get; init; }
        public bool Closed { get; set; }
    }

    /// <summary>
    /// Enough of ConnectWise's REST API to file a ticket: checks the credential
    /// the way the real one does, and keeps what was filed.
    /// </summary>
    internal sealed class FakeConnectWise : HttpMessageHandler
    {
        private int _next = 500;

        public string ExpectedAuthorization { get; set; } = "";
        public string ExpectedClientId { get; set; } = "";
        public HashSet<string> Boards { get; } = new(StringComparer.Ordinal) { "Alerts" };
        public List<(int Id, string Identifier, string Name)> Companies { get; } = [(1001, "ACME", "Acme Corp"), (1002, "GLOBEX", "Globex Inc")];
        public Dictionary<int, FakeTicket> Tickets { get; } = [];
        public List<(int Ticket, string Text)> Notes { get; } = [];
        public HttpStatusCode? Fail { get; set; }
        public bool LoseNextCreateAnswer { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string? Header(string name) => request.Headers.TryGetValues(name, out var values) ? values.Single() : null;

            if (Header("Authorization") != "Basic " + ExpectedAuthorization || Header("clientId") != ExpectedClientId)
            {
                return Answer(HttpStatusCode.Unauthorized, """{"code":"Unauthorized","message":"Invalid credentials or clientId"}""");
            }

            if (Fail is { } fail) { return Answer(fail, """{"message":"ConnectWise is restarting"}"""); }

            var path = request.RequestUri!.AbsolutePath;
            const string prefix = "/v4_6_release/apis/3.0/";
            Assert.StartsWith(prefix, path, StringComparison.Ordinal);
            var relative = path[prefix.Length..];
            var query = Uri.UnescapeDataString(request.RequestUri.Query.TrimStart('?'));
            var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);

            if (request.Method == HttpMethod.Get && relative == "company/companies")
            {
                var text = Quoted(query);
                var matches = text is null
                    ? Companies.Take(1)
                    : Companies.Where(c => c.Name.Contains(text, StringComparison.OrdinalIgnoreCase) || c.Identifier.Contains(text, StringComparison.OrdinalIgnoreCase));
                return Answer(HttpStatusCode.OK, "[" + string.Join(",", matches.Select(c => $$"""{"id":{{c.Id}},"identifier":"{{c.Identifier}}","name":"{{c.Name}}"}""")) + "]");
            }

            if (request.Method == HttpMethod.Get && relative == "service/boards")
            {
                var name = Quoted(query) ?? "";
                return Answer(HttpStatusCode.OK, Boards.Contains(name) ? $$"""[{"id":1,"name":"{{name}}"}]""" : "[]");
            }

            if (request.Method == HttpMethod.Get && relative == "service/tickets")
            {
                var marker = Quoted(query) ?? "";
                var found = Tickets.Values.Where(t => t.Summary.Contains(marker, StringComparison.Ordinal)).Select(TicketJson);
                return Answer(HttpStatusCode.OK, "[" + string.Join(",", found) + "]");
            }

            var ticketMatch = Regex.Match(relative, @"^service/tickets/(\d+)(/notes)?$");
            if (ticketMatch.Success)
            {
                var id = int.Parse(ticketMatch.Groups[1].Value, CultureInfo.InvariantCulture);
                if (!Tickets.TryGetValue(id, out var ticket))
                {
                    return Answer(HttpStatusCode.NotFound, """{"code":"NotFound","message":"Ticket not found"}""");
                }

                if (request.Method == HttpMethod.Post && ticketMatch.Groups[2].Success)
                {
                    using var note = JsonDocument.Parse(body!);
                    Notes.Add((id, note.RootElement.GetProperty("text").GetString()!));
                    return Answer(HttpStatusCode.Created, $$"""{"id":{{Notes.Count}},"text":"ok"}""");
                }

                if (request.Method == HttpMethod.Get)
                {
                    return Answer(HttpStatusCode.OK, TicketJson(ticket));
                }
            }

            if (request.Method == HttpMethod.Post && relative == "service/tickets")
            {
                using var doc = JsonDocument.Parse(body!);
                var root = doc.RootElement;
                var created = new FakeTicket
                {
                    Id = _next++,
                    Summary = root.GetProperty("summary").GetString()!,
                    Board = root.GetProperty("board").GetProperty("name").GetString()!,
                    CompanyId = root.GetProperty("company").GetProperty("id").GetInt32(),
                    Status = root.TryGetProperty("status", out var status) ? status.GetProperty("name").GetString() : null,
                    Priority = root.TryGetProperty("priority", out var priority) ? priority.GetProperty("name").GetString() : null,
                    Description = root.GetProperty("initialDescription").GetString()!,
                };
                Tickets[created.Id] = created;

                if (LoseNextCreateAnswer)
                {
                    LoseNextCreateAnswer = false;
                    return Answer(HttpStatusCode.BadGateway, "");
                }
                return Answer(HttpStatusCode.Created, TicketJson(created));
            }

            return Answer(HttpStatusCode.NotFound, $$"""{"message":"no route for {{request.Method}} {{relative}}"}""");
        }

        private static string? Quoted(string query)
        {
            var match = Regex.Match(query, "\"([^\"]*)\"");
            return match.Success ? match.Groups[1].Value : null;
        }

        private static string TicketJson(FakeTicket t) =>
            JsonSerializer.Serialize(new { id = t.Id, summary = t.Summary, closedFlag = t.Closed, status = new { name = t.Status ?? "New" } });

        private static HttpResponseMessage Answer(HttpStatusCode status, string json) =>
            new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    }

    /// <summary>A webhook receiver that counts, for the test that feeds both kinds at once.</summary>
    private sealed class RecordingWebhook : HttpMessageHandler
    {
        public int Posts { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Posts++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") });
        }
    }

    /// <summary>One handler for both destinations, by host.</summary>
    private sealed class Router(HttpMessageHandler connectWise, HttpMessageHandler webhook) : HttpMessageHandler
    {
        private readonly HttpMessageInvoker _cw = new(connectWise, disposeHandler: false);
        private readonly HttpMessageInvoker _hook = new(webhook, disposeHandler: false);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            request.RequestUri!.Host == "cw.example"
                ? _cw.SendAsync(request, cancellationToken)
                : _hook.SendAsync(request, cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (disposing) { _cw.Dispose(); _hook.Dispose(); }
            base.Dispose(disposing);
        }
    }
}

/// <summary>
/// Migration 0021 rebuilds the two notification tables. A rebuild is the
/// shape of migration that has lost rows before (see DatabaseMigrationTests),
/// so this one is proved against rows, on the connection settings the product
/// runs with.
/// </summary>
public sealed class DestinationMigrationTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-cw-migrate-{Guid.NewGuid():N}.db");

    public void Dispose() => SingleDatabase.Delete(_dbPath);

    [Fact]
    public async Task TheRebuildKeepsEveryDestinationAndDeliveryAndAllowsOneOfEachKind()
    {
        // A database as the release before this left it: the frozen single
        // schema, with everything up to 0020 applied as SQL, and a webhook
        // that has delivered something.
        await using (var db = Open())
        {
            await RunAsync(db, SingleDatabase.Schema);
        }
        await DatabaseMigrations.ApplyAsync(_dbPath,
            [.. DatabaseMigrations.All.Where(m => string.CompareOrdinal(m.Version, "0021") < 0)]);

        const string when = "2026-09-20 00:00:00";
        await using (var db = Open())
        {
            await RunAsync(db, $"""
                INSERT INTO tenants (id,slug,name,created_at,updated_at) VALUES ('t1','local','Local','{when}','{when}');
                INSERT INTO clients (id,tenant_id,slug,name,created_at,updated_at) VALUES ('c1','t1','acme','Acme','{when}','{when}');
                INSERT INTO webhooks (id,tenant_id,destination,credential_ref,min_severity,link_base,created_at,created_by,updated_at,last_delivered_at)
                  VALUES ('w1','t1','https://console.example','dmarc.local.webhook.0123456789abcdef','warning',NULL,'{when}','tester','{when}','{when}');
                INSERT INTO webhook_deliveries (webhook_id,event_id,client_id,attempts,delivered_at,last_attempt_at,last_status)
                  VALUES ('w1','e1','c1',1,'{when}','{when}',200), ('w1','e2','c1',2,NULL,'{when}',503);
                """);
        }

        var result = await DatabaseMigrations.ApplyAsync(_dbPath);

        Assert.Contains(result.Applied, a => a.StartsWith("0021", StringComparison.Ordinal));
        await using (var db = Open())
        {
            Assert.Equal(1L, await ScalarAsync(db, "SELECT COUNT(*) FROM webhooks WHERE id = 'w1' AND kind = 'webhook' AND last_delivered_at IS NOT NULL"));
            Assert.Equal(2L, await ScalarAsync(db, "SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id = 'w1'"));
            Assert.Equal(503L, await ScalarAsync(db, "SELECT last_status FROM webhook_deliveries WHERE event_id = 'e2'"));
            Assert.Equal(0L, await ScalarAsync(db, "SELECT COUNT(*) FROM pragma_foreign_key_check"));

            // The point of the rebuild: a second kind beside the first, and
            // still only one of each.
            await RunAsync(db, $"""
                INSERT INTO webhooks (id,tenant_id,kind,destination,credential_ref,created_at,created_by,updated_at)
                  VALUES ('w2','t1','connectwise','https://cw.example','dmarc.local.connectwise.0123456789abcdef','{when}','tester','{when}');
                """);
            await Assert.ThrowsAsync<SqliteException>(() => RunAsync(db, $"""
                INSERT INTO webhooks (id,tenant_id,kind,destination,credential_ref,created_at,created_by,updated_at)
                  VALUES ('w3','t1','connectwise','https://other.example','dmarc.local.connectwise.fedcba9876543210','{when}','tester','{when}');
                """));

            // And the child still follows the parent: deleting a destination takes its ledger.
            await RunAsync(db, "DELETE FROM webhooks WHERE id = 'w1'");
            Assert.Equal(0L, await ScalarAsync(db, "SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id = 'w1'"));
        }
    }

    private SqliteConnection Open()
    {
        var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _dbPath, ForeignKeys = true, Pooling = false }.ToString());
        db.Open();
        return db;
    }

    private static async Task RunAsync(SqliteConnection db, string sql)
    {
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<object?> ScalarAsync(SqliteConnection db, string sql)
    {
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteScalarAsync();
    }
}
