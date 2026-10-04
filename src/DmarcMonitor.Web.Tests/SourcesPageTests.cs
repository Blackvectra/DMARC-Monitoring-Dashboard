using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Intelligence;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Web.Components.Pages;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// The failing-sources page: one row per sender, the addresses behind it, and
/// the controls for reading a long list.
///
/// The page used to be one row per address. On a real estate that was forty-odd
/// rows, fourteen of them Microsoft, with the same explanatory sentence under
/// each and the one pattern worth seeing - one hosting provider working through
/// three customers - spread across four unrelated-looking lines.
/// </summary>
public sealed class SourcesPageTests : IClassFixture<SendersApp>
{
    private readonly SendersApp _app;

    public SourcesPageTests(SendersApp app) => _app = app;

    private HttpClient Client() => _app.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = true,
        HandleCookies = true,
    });

    /// <summary>The one table row that mentions <paramref name="needle"/>.</summary>
    private static string Row(string html, string needle) =>
        html.Split("<tr").Skip(1).Single(row => row.Contains(needle, StringComparison.Ordinal));

    private static int RowCount(string html) => html.Split("<tr").Length - 2;   // the header is one, and the text before the first

    // ---- what the page shows -------------------------------------------------

    /// <summary>
    /// The pattern the page exists to show: three addresses at one host, three
    /// customers, one line. As three rows it reads as three unrelated nuisances.
    /// </summary>
    [Fact]
    public async Task AnOperatorsAddressesAreOneRowWithTheAddressesBehindIt()
    {
        var html = await Client().GetStringAsync("/sources");
        var row = Row(html, "hostile.example");

        Assert.Contains("3 addresses", row, StringComparison.Ordinal);
        Assert.Contains("<strong>3</strong> parties", row, StringComparison.Ordinal);

        // Behind the row rather than gone: they are the identity, and blocking
        // is done by address.
        foreach (var ip in new[] { "203.0.113.21", "203.0.113.22", "203.0.113.23" })
        {
            Assert.Contains($"/sources/{ip}", row, StringComparison.Ordinal);
        }

        // Named after the domain they claim, and said to be a claim: nothing
        // pointed back at these addresses, so "ColoCrossing-style" vendor names
        // would be this product vouching for them.
        Assert.Contains("names not confirmed", row, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AMailProviderIsOneRowAndIsNotCalledAFinding()
    {
        var html = await Client().GetStringAsync("/sources");
        var row = Row(html, "Microsoft 365");

        Assert.Contains("3 addresses", row, StringComparison.Ordinal);
        Assert.DoesNotContain("names not confirmed", row, StringComparison.Ordinal);

        // Spanning clients is for an operator, not for the size of a provider:
        // the count names only the one host above.
        Assert.Contains("1 spanning clients", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnAddressWithNoNameStillPrintsAsAnAddress()
    {
        // The state every install is in for its first night.
        var row = Row(await Client().GetStringAsync("/sources"), "203.0.113.99");

        Assert.Contains("/sources/203.0.113.99", row, StringComparison.Ordinal);
        Assert.DoesNotContain("addresses", row, StringComparison.Ordinal);
    }

    /// <summary>
    /// A word beside every row, and not only a color: about one man in twelve
    /// cannot tell the red from the orange, and this column is the reason the
    /// page exists.
    /// </summary>
    [Fact]
    public async Task EveryRowSaysInWordsWhatItLooksLike()
    {
        var html = await Client().GetStringAsync("/sources");

        Assert.Contains("Cross-client", Row(html, "203.0.113.50"), StringComparison.Ordinal);
        Assert.Contains("Unauthenticated", Row(html, "hostile.example"), StringComparison.Ordinal);
        Assert.Contains("Unaligned service", Row(html, "147.160.167.15"), StringComparison.Ordinal);
        Assert.Contains("Own sending path", Row(html, "192.0.2.25"), StringComparison.Ordinal);
    }

    /// <summary>
    /// The sentence that used to be repeated under every row is said once, in a
    /// key, and still says the cautious thing: the relay that is failing is not
    /// somebody sending as the client.
    /// </summary>
    [Fact]
    public async Task TheKeyExplainsEachLabelOnce()
    {
        var html = await Client().GetStringAsync("/sources");

        Assert.Contains("What the labels mean", html, StringComparison.Ordinal);

        // Once on the page, not once per row.
        Assert.Equal(1, html.Split("not somebody sending as them").Length - 1);
        Assert.Equal(1, html.Split("One would be noise; several is somebody working through a list").Length - 1);
    }

    [Fact]
    public async Task SaysHowManyAddressesStillHaveNoName()
    {
        var html = await Client().GetStringAsync("/sources");

        // "Due", which covers a name that is old or never checked as well as an
        // address nobody has asked about: "40 of 40 have a name; 40 have not been
        // looked up" was a sentence that contradicted itself.
        Assert.Contains("are due a lookup", html, StringComparison.Ordinal);
        Assert.DoesNotContain("have not been looked up yet", html, StringComparison.Ordinal);
        Assert.Contains("Look up names now", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// What the lookup says is announced to somebody who cannot see it change,
    /// and the key is not the chart legend's: they once shared a class name,
    /// and with it a flex row that put the definitions beside the summary.
    /// </summary>
    [Fact]
    public async Task TheStatusIsAnAnnouncedRegionAndTheKeyHasAHookOfItsOwn()
    {
        var html = await Client().GetStringAsync("/sources");

        Assert.Contains("role=\"status\"", html, StringComparison.Ordinal);
        Assert.Contains("<details class=\"label-key\">", html, StringComparison.Ordinal);
        Assert.DoesNotContain("class=\"key\"", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A sender whose addresses each reached one party but together reached
    /// three reads Unauthenticated, the worst of them. Its hover must not say
    /// "against one client so far" beside a red "3 parties".
    /// </summary>
    [Fact]
    public async Task ASenderSpanningClientsSaysSoOnHoverRatherThanContradictingItsOwnRow()
    {
        var row = Row(await Client().GetStringAsync("/sources"), "hostile.example");

        // The row's own label, not the per-address ones inside it.
        var label = System.Text.RegularExpressions.Regex.Match(
            row, "<span class=\"count act\" title=\"([^\"]+)\">Unauthenticated</span>");

        Assert.True(label.Success, row);
        Assert.Contains("together the addresses reached 3", label.Groups[1].Value, StringComparison.Ordinal);
        Assert.DoesNotContain("one client so far", label.Groups[1].Value, StringComparison.Ordinal);
    }

    // ---- using it ------------------------------------------------------------

    private static readonly string[] BusiestFirst =
    [
        "147.160.167.15",   // 289
        "192.0.2.25",       // 40
        "hostile.example",  // 15
        "198.51.100.77",    // 9
        "Microsoft 365",    // 6
        "203.0.113.99",     // 1
    ];

    private static bool InOrder(string html, IEnumerable<string> expected)
    {
        var at = -1;
        foreach (var needle in expected)
        {
            var next = html.IndexOf(needle, at + 1, StringComparison.Ordinal);
            if (next < 0 || next < at) { return false; }
            at = next;
        }

        return true;
    }

    [Fact]
    public async Task OpensWithTheWorstFirst()
    {
        await using var page = await LivePage.OpenAsync<Sources>(_app);

        var html = await page.HtmlAsync();

        // Severity, not volume: the cross-client address is first though it
        // failed only six times, and nothing that merely failed a lot outranks it.
        Assert.True(InOrder(html, ["203.0.113.50", "hostile.example", "147.160.167.15", "192.0.2.25"]), html);
    }

    [Fact]
    public async Task SortingByFailedPutsTheBusiestFirstAndASecondPressReversesIt()
    {
        await using var page = await LivePage.OpenAsync<Sources>(_app);

        await page.ClickAsync(label => label.StartsWith("Failed", StringComparison.Ordinal), "the Failed header");
        var busiest = await page.HtmlAsync();
        Assert.True(InOrder(busiest, BusiestFirst), busiest);
        Assert.Contains("aria-sort=\"descending\"", busiest, StringComparison.Ordinal);

        await page.ClickAsync(label => label.StartsWith("Failed", StringComparison.Ordinal), "the Failed header");
        var quietest = await page.HtmlAsync();
        Assert.True(
            InOrder(quietest, ["203.0.113.99", "Microsoft 365", "198.51.100.77", "hostile.example", "192.0.2.25", "147.160.167.15"]),
            quietest);
        Assert.Contains("aria-sort=\"ascending\"", quietest, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SortingByNameStartsAtA()
    {
        await using var page = await LivePage.OpenAsync<Sources>(_app);

        await page.ClickAsync(label => label.StartsWith("Sender", StringComparison.Ordinal), "the Sender header");

        var html = await page.HtmlAsync();
        Assert.Contains("aria-sort=\"ascending\"", html, StringComparison.Ordinal);
        Assert.True(InOrder(html, ["hostile.example", "INKY", "Microsoft 365"]), html);
    }

    [Fact]
    public async Task TypingNarrowsTheListAndAnEmptyResultSaysSo()
    {
        await using var page = await LivePage.OpenAsync<Sources>(_app);

        await page.TypeAsync("Find a sender, address or domain", "hostile");
        var narrowed = await page.HtmlAsync();
        Assert.Contains("hostile.example", narrowed, StringComparison.Ordinal);
        Assert.DoesNotContain("Microsoft 365", narrowed, StringComparison.Ordinal);

        // By an address inside a group too: it is how somebody finds the row
        // for a line out of a firewall log.
        await page.TypeAsync("Find a sender, address or domain", "203.0.113.22");
        Assert.Contains("hostile.example", await page.HtmlAsync(), StringComparison.Ordinal);

        // And by the domain it was seen against.
        await page.TypeAsync("Find a sender, address or domain", "gamma.example");
        var byDomain = await page.HtmlAsync();
        Assert.Contains("hostile.example", byDomain, StringComparison.Ordinal);
        Assert.Contains("Microsoft 365", byDomain, StringComparison.Ordinal);
        Assert.DoesNotContain("147.160.167.15", byDomain, StringComparison.Ordinal);

        await page.TypeAsync("Find a sender, address or domain", "zzz-matches-nothing");
        var none = await page.HtmlAsync();

        // An empty table under a search box reads as "nothing is failing",
        // which is not what happened.
        Assert.Contains("Nothing matches.", none, StringComparison.Ordinal);

        await page.ClickAsync(label => label.StartsWith("Show all", StringComparison.Ordinal), "Show all");
        var restored = await page.HtmlAsync();
        Assert.DoesNotContain("Nothing matches.", restored, StringComparison.Ordinal);
        Assert.Contains("Microsoft 365", restored, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PressingALabelShowsOnlyThoseSendersAndPressingItAgainShowsAll()
    {
        await using var page = await LivePage.OpenAsync<Sources>(_app);

        await page.ClickAsync(label => label.EndsWith("Unaligned service", StringComparison.Ordinal), "the Unaligned service count");
        var only = await page.HtmlAsync();
        Assert.Contains("147.160.167.15", only, StringComparison.Ordinal);
        Assert.DoesNotContain("hostile.example", only, StringComparison.Ordinal);
        Assert.Contains("aria-pressed=\"true\"", only, StringComparison.Ordinal);

        await page.ClickAsync(label => label.EndsWith("Unaligned service", StringComparison.Ordinal), "the Unaligned service count");
        Assert.Contains("hostile.example", await page.HtmlAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task SpanningClientsShowsTheOperatorAndNotTheProvider()
    {
        await using var page = await LivePage.OpenAsync<Sources>(_app);

        await page.ClickAsync(label => label.EndsWith("spanning clients", StringComparison.Ordinal), "the spanning clients count");

        var html = await page.HtmlAsync();
        Assert.Contains("hostile.example", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Microsoft 365", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// For the person who wants the old list back, to read addresses off one
    /// line each.
    /// </summary>
    [Fact]
    public async Task GroupingCanBeTurnedOffToSeeEveryAddress()
    {
        await using var page = await LivePage.OpenAsync<Sources>(_app);

        // Seven senders, one of them three addresses and one of them three more.
        Assert.Equal(7, RowCount(await page.HtmlAsync()));

        await page.ToggleAsync("Group by sender", on: false);

        var html = await page.HtmlAsync();
        Assert.Equal(11, RowCount(html));
        Assert.DoesNotContain("3 addresses", html, StringComparison.Ordinal);

        await page.ToggleAsync("Group by sender", on: true);
        Assert.Equal(7, RowCount(await page.HtmlAsync()));
    }

    [Fact]
    public async Task SwitchingTheWindowKeepsTheControlsWorking()
    {
        await using var page = await LivePage.OpenAsync<Sources>(_app);

        await page.ChooseAsync("7", "7");
        await page.ChooseAsync("7", "90");
        await page.TypeAsync("Find a sender, address or domain", "hostile");

        Assert.Contains("hostile.example", await page.HtmlAsync(), StringComparison.Ordinal);
    }
}

/// <summary>
/// The name lookup, apart from the rest because it writes: what it stores is
/// exactly what the read-only tests next door count on being absent, and a
/// fixture is shared by every test in its class.
/// </summary>
public sealed class SourceNameLookupTests : IClassFixture<SendersApp>
{
    private readonly SendersApp _app;

    public SourceNameLookupTests(SendersApp app) => _app = app;

    /// <summary>
    /// The Windows trial has no nightly job, so a table of bare addresses would
    /// stay one for ever. The button names the ones on screen.
    /// </summary>
    [Fact]
    public async Task LookUpNamesNamesTheAddressesOnScreenAndThenGoesAway()
    {
        await using var page = await LivePage.OpenAsync<Sources>(_app);
        var before = await page.HtmlAsync();
        Assert.Contains("Look up names now", before, StringComparison.Ordinal);

        var store = new SourceNameStore(_app.DatabasePath);
        Assert.Empty(await store.GetAsync(["203.0.113.99"]));

        await page.ClickAsync("Look up names now");

        // Asked, and recorded as asked - with nothing found, because this
        // install is cut off from the network. What matters is that the answer
        // is kept so tomorrow does not ask again.
        var after = await page.HtmlAsync();
        Assert.Contains("Looked up 4 source(s)", after, StringComparison.Ordinal);
        Assert.DoesNotContain("Look up names now", after, StringComparison.Ordinal);
        Assert.True((await store.GetAsync(["203.0.113.99"])).ContainsKey("203.0.113.99"));
    }
}

/// <summary>
/// The same press, read from the audit log. Its own fixture, like the lookup
/// above, because the press writes and a second one would find nothing left to do.
/// </summary>
public sealed class SourceNameLookupAuditTests : IClassFixture<SendersApp>
{
    private readonly SendersApp _app;

    public SourceNameLookupAuditTests(SendersApp app) => _app = app;

    /// <summary>
    /// It reaches outside the machine, so a burst of lookups against somebody's
    /// resolver has to be attributable to whoever kept pressing the button.
    /// </summary>
    [Fact]
    public async Task APressIsInTheAuditLogAgainstWhoPressedIt()
    {
        await using var page = await LivePage.OpenAsync<Sources>(_app);

        await page.ClickAsync("Look up names now");

        var entry = Assert.Single(
            await new DmarcMonitor.Core.Tenancy.AuditLog(_app.DatabasePath).ListAsync(),
            e => e.Action == "sources.names");
        Assert.Equal("operator@example.com", entry.Actor);
        Assert.Contains("4 address(es)", entry.Detail, StringComparison.Ordinal);
    }
}

/// <summary>
/// The seeded install with a hosting provider working through three customers,
/// a mail provider answering from three addresses, and an address that crossed
/// two customers on its own - and no network, so a name lookup finds nothing
/// at once rather than waiting out a timeout.
/// </summary>
public sealed class SendersApp : SeededApp
{
    public SendersApp() => Extend().GetAwaiter().GetResult();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureTestServices(services => services.AddSingleton(new DnsLookup(NoNetwork.Resolver())));
    }

    private async Task Extend()
    {
        var store = new ReportStore(DatabasePath);

        // Three domains nobody has filed, so each is a party of its own.
        await StoreAsync(store, "alpha.example", ("203.0.113.21", 5), ("198.51.100.201", 2), ("203.0.113.99", 1), ("203.0.113.50", 3));
        await StoreAsync(store, "beta.example", ("203.0.113.22", 5), ("198.51.100.202", 2), ("203.0.113.50", 3));
        await StoreAsync(store, "gamma.example", ("203.0.113.23", 5), ("198.51.100.203", 2));

        var names = new SourceNameStore(DatabasePath);

        // Reverse names that point nowhere: a host whose PTRs have no forward
        // records, which is what ColoCrossing's look like on real data.
        foreach (var (ip, name) in new[]
        {
            ("203.0.113.21", "a-host.hostile.example"),
            ("203.0.113.22", "b-host.hostile.example"),
            ("203.0.113.23", "c-host.hostile.example"),
        })
        {
            await names.SaveAsync(ip, name, answered: true, forwardConfirmed: false);
        }

        // And Microsoft's, which do.
        foreach (var (ip, name) in new[]
        {
            ("198.51.100.201", "mail-a.outbound.protection.outlook.com"),
            ("198.51.100.202", "mail-b.outbound.protection.outlook.com"),
            ("198.51.100.203", "mail-c.outbound.protection.outlook.com"),
        })
        {
            await names.SaveAsync(ip, name, answered: true, forwardConfirmed: true);
        }
    }

    private static async Task StoreAsync(ReportStore store, string domain, params (string Ip, int Count)[] failing)
    {
        var begin = DateTimeOffset.UtcNow.AddDays(-2);
        var records = string.Concat(failing.Select(f => $"""
            <record>
              <row>
                <source_ip>{f.Ip}</source_ip><count>{f.Count}</count>
                <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
              </row>
              <identifiers><header_from>{domain}</header_from></identifiers>
              <auth_results>
                <dkim><domain>{domain}</domain><result>fail</result></dkim>
                <spf><domain>{domain}</domain><result>fail</result></spf>
              </auth_results>
            </record>
            """));

        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>google.com</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin>
                            <end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>{domain}</domain><p>none</p><pct>100</pct></policy_published>
              {records}
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        if (!parsed.Success) { throw new InvalidOperationException($"seed report did not parse: {parsed.Error}"); }
        await store.SaveAggregateAsync(parsed.Report!, xml, null);
    }
}
