using System.Text.RegularExpressions;
using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Storage;
using Microsoft.AspNetCore.Mvc.Testing;
using DomainsPage = DmarcMonitor.Web.Components.Pages.Domains;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// The domains table: one table however it is grouped, columns that order it,
/// and a client's domains together under its name.
///
/// It used to be one table per client. Twenty clients meant twenty header
/// rows and twenty sets of columns, each sized to its own contents, none of
/// them lining up with the one above.
/// </summary>
public sealed class DomainsPageTests : IClassFixture<BookApp>
{
    private readonly BookApp _app;

    public DomainsPageTests(BookApp app) => _app = app;

    private Task<string> PageAsync() => _app
        .CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = true, HandleCookies = true })
        .GetStringAsync("/domains");

    /// <summary>The one table row that mentions <paramref name="needle"/>.</summary>
    private static string Row(string html, string needle) =>
        html.Split("<tr").Skip(1).Single(row => row.Contains(needle, StringComparison.Ordinal));

    private static bool InOrder(string html, params string[] expected)
    {
        var at = -1;
        foreach (var needle in expected)
        {
            var next = html.IndexOf(needle, at + 1, StringComparison.Ordinal);
            if (next < 0) { return false; }
            at = next;
        }

        return true;
    }

    private static int Headings(string html) => html.Split("scope=\"rowgroup\"").Length - 1;

    // ---- the table -----------------------------------------------------------

    [Fact]
    public async Task IsOneTableWithOneHeaderWhateverTheGrouping()
    {
        var html = await PageAsync();

        Assert.Equal(1, html.Split("<table").Length - 1);
        Assert.Equal(1, html.Split("<thead").Length - 1);
    }

    /// <summary>
    /// A client's domains sit under its name, and the table stays in domain
    /// order: the block is where its first domain would have been, and its
    /// other domain is brought up beside it.
    /// </summary>
    [Fact]
    public async Task AClientsDomainsSitTogetherUnderItsNameAndTheTableStaysInDomainOrder()
    {
        var html = await PageAsync();

        Assert.Equal(2, Headings(html));
        Assert.Contains("Acme Corp", html, StringComparison.Ordinal);
        Assert.Contains("Charlie LLC", html, StringComparison.Ordinal);

        // signed.example is pulled up under acme.com rather than staying
        // where the alphabet would put it, at the bottom.
        Assert.True(InOrder(html, "Acme Corp", "acme.com", "signed.example", "bravo.example", "Charlie LLC", "charlie.example", "delta.example"), html);
    }

    [Fact]
    public async Task ADomainSaysWhoseItIsOnlyWhereNoHeadingAlreadyDoes()
    {
        var html = await PageAsync();

        // Under no heading, so it says.
        Assert.Contains("Bravo Inc", Row(html, "bravo.example"), StringComparison.Ordinal);

        // Under Acme's heading, which says it once for both.
        Assert.DoesNotContain("Acme Corp", Row(html, "signed.example"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task EveryStatusDotHasANameForAScreenReader()
    {
        var html = await PageAsync();

        // The dot alone is a color. Every one of them says in words what it
        // stands for, and a domain with something to do says what.
        var dots = Regex.Matches(html, @"class=""pip [a-z]+"" role=""img"" aria-label=""([^""]+)""");

        Assert.Equal(5, dots.Count);
        Assert.All(dots, d => Assert.Matches(@"^(Urgent|Act|Watch|On track|Fine)", d.Groups[1].Value));
    }

    [Fact]
    public async Task CountsHowManyDomainsAreAtEachPolicy()
    {
        var html = await PageAsync();

        // acme.com and signed.example publish p=reject; the three others p=none.
        Assert.Contains("3 p=none", html, StringComparison.Ordinal);
        Assert.Contains("2 p=reject", html, StringComparison.Ordinal);
        Assert.DoesNotContain("p=quarantine</button>", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnreadRecordsAreOneQuietStripRatherThanFiveBoxesPerRow()
    {
        var html = await PageAsync();

        Assert.Contains("records unread", html, StringComparison.Ordinal);

        // Still five indicators per row for a screen reader to be told.
        Assert.Equal(5, Regex.Count(Row(html, "bravo.example"), "role=\"img\" aria-label=\"[A-Z-]+ for bravo.example"));
    }

    // ---- using it ------------------------------------------------------------

    [Fact]
    public async Task PressingVolumeOrdersByItBusiestFirstAndTakesTheGroupingApart()
    {
        await using var page = await LivePage.OpenAsync<DomainsPage>(_app);

        await page.ClickAsync(label => label.StartsWith("Volume", StringComparison.Ordinal), "the Volume header");

        var html = await page.HtmlAsync();

        // acme 1,000, bravo 550, signed 324, charlie 100, delta 60.
        Assert.True(InOrder(html, "acme.com", "bravo.example", "signed.example", "charlie.example", "delta.example"), html);
        Assert.Contains("aria-sort=\"descending\"", html, StringComparison.Ordinal);

        // Ordered by anything but name, it is one list across every client:
        // a reader pressing a column is asking which domains, not which
        // domains within each client.
        Assert.Equal(0, Headings(html));
    }

    [Fact]
    public async Task PressingPassingPutsTheWorstFirstAndASecondPressReversesIt()
    {
        await using var page = await LivePage.OpenAsync<DomainsPage>(_app);

        await page.ClickAsync(label => label.StartsWith("Passing", StringComparison.Ordinal), "the Passing header");

        // signed 4.3%, delta 50%, bravo 90.9%, acme 96%, charlie 100%.
        var worst = await page.HtmlAsync();
        Assert.True(InOrder(worst, "signed.example", "delta.example", "bravo.example", "acme.com", "charlie.example"), worst);
        Assert.Contains("aria-sort=\"ascending\"", worst, StringComparison.Ordinal);

        await page.ClickAsync(label => label.StartsWith("Passing", StringComparison.Ordinal), "the Passing header");

        var best = await page.HtmlAsync();
        Assert.True(InOrder(best, "charlie.example", "acme.com", "bravo.example", "delta.example", "signed.example"), best);
    }

    [Fact]
    public async Task PressingNameAgainBringsTheGroupingBack()
    {
        await using var page = await LivePage.OpenAsync<DomainsPage>(_app);

        await page.ClickAsync(label => label.StartsWith("Volume", StringComparison.Ordinal), "the Volume header");
        Assert.Equal(0, Headings(await page.HtmlAsync()));

        await page.ClickAsync(label => label.StartsWith("Domain", StringComparison.Ordinal), "the Domain header");

        var html = await page.HtmlAsync();
        Assert.Equal(2, Headings(html));
        Assert.Contains("aria-sort=\"ascending\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheGroupingBoxIsInertWhileAnotherColumnOrdersTheTable()
    {
        await using var page = await LivePage.OpenAsync<DomainsPage>(_app);

        Assert.DoesNotContain("disabled", Regex.Match(await page.HtmlAsync(), @"<input[^>]*type=""checkbox""[^>]*>").Value, StringComparison.Ordinal);

        await page.ClickAsync(label => label.StartsWith("Volume", StringComparison.Ordinal), "the Volume header");

        // Said, rather than a box that is ticked and does nothing.
        var html = await page.HtmlAsync();
        Assert.Contains("Off while the table is ordered by another column.", html, StringComparison.Ordinal);
        Assert.Contains("disabled", Regex.Match(html, @"<input[^>]*type=""checkbox""[^>]*>").Value, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PressingAPolicyCountShowsOnlyThoseDomains()
    {
        await using var page = await LivePage.OpenAsync<DomainsPage>(_app);

        await page.ClickAsync(label => label.EndsWith("p=none", StringComparison.Ordinal), "the p=none count");

        var html = await page.HtmlAsync();
        Assert.Contains("bravo.example", html, StringComparison.Ordinal);
        Assert.Contains("delta.example", html, StringComparison.Ordinal);
        Assert.DoesNotContain("acme.com", html, StringComparison.Ordinal);
        Assert.Contains("3 of 5", html, StringComparison.Ordinal);

        // Charlie's two domains are both at none, so they keep their heading.
        Assert.Equal(1, Headings(html));

        await page.ClickAsync(label => label.EndsWith("p=none", StringComparison.Ordinal), "the p=none count");
        Assert.Contains("acme.com", await page.HtmlAsync(), StringComparison.Ordinal);
    }

    /// <summary>
    /// A heading over one row is the row said twice, so narrowing a client to
    /// one domain drops it - and the domain says whose it is instead.
    /// </summary>
    [Fact]
    public async Task NarrowingAClientToOneDomainDropsItsHeadingAndNamesTheClientUnderTheDomain()
    {
        await using var page = await LivePage.OpenAsync<DomainsPage>(_app);

        await page.TypeAsync("Filter by domain or client", "delta");

        var html = await page.HtmlAsync();
        Assert.Equal(0, Headings(html));
        Assert.Contains("Charlie LLC", Row(html, "delta.example"), StringComparison.Ordinal);
        Assert.DoesNotContain("charlie.example", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TypingAClientsNameKeepsAllItsDomainsUnderItsHeading()
    {
        await using var page = await LivePage.OpenAsync<DomainsPage>(_app);

        await page.TypeAsync("Filter by domain or client", "acme corp");

        var html = await page.HtmlAsync();
        Assert.Equal(1, Headings(html));
        Assert.Contains("acme.com", html, StringComparison.Ordinal);
        Assert.Contains("signed.example", html, StringComparison.Ordinal);
        Assert.DoesNotContain("bravo.example", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AFilterThatMatchesNothingSaysSoAndCanBeCleared()
    {
        await using var page = await LivePage.OpenAsync<DomainsPage>(_app);

        await page.TypeAsync("Filter by domain or client", "zzz-matches-nothing");
        Assert.Contains("Nothing matches.", await page.HtmlAsync(), StringComparison.Ordinal);

        await page.ClickAsync(label => label.StartsWith("Show all", StringComparison.Ordinal), "Show all");

        var html = await page.HtmlAsync();
        Assert.DoesNotContain("Nothing matches.", html, StringComparison.Ordinal);
        Assert.Contains("bravo.example", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GroupingCanBeTurnedOffForOnePlainAlphabeticalList()
    {
        await using var page = await LivePage.OpenAsync<DomainsPage>(_app);

        await page.ToggleAsync("Group by client", on: false);

        var html = await page.HtmlAsync();
        Assert.Equal(0, Headings(html));
        Assert.True(InOrder(html, "acme.com", "bravo.example", "charlie.example", "delta.example", "signed.example"), html);

        // And every domain says whose it is, since nothing else does.
        Assert.Contains("Acme Corp", Row(html, "signed.example"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ChoosingAClientShowsThatClientAndSwitchingTheWindowKeepsTheControlsWorking()
    {
        await using var page = await LivePage.OpenAsync<DomainsPage>(_app);

        await page.ChooseAsync("bravo-inc", "bravo-inc");
        var one = await page.HtmlAsync();
        Assert.Contains("bravo.example", one, StringComparison.Ordinal);
        Assert.DoesNotContain("acme.com", one, StringComparison.Ordinal);

        await page.ChooseAsync("7", "90");
        await page.ClickAsync(label => label.StartsWith("Volume", StringComparison.Ordinal), "the Volume header");
        Assert.Contains("bravo.example", await page.HtmlAsync(), StringComparison.Ordinal);
    }
}

/// <summary>
/// Two clients that happen to share a name, each with two domains.
/// </summary>
/// <remarks>
/// Only a redraw finds out whether the rows have distinct keys - the first draw
/// compares nothing - so this is a test of what happens when somebody presses
/// a column, not of what the page looks like when it opens.
/// </remarks>
public sealed class TwinClientsTests : IClassFixture<TwinClientsApp>
{
    private readonly TwinClientsApp _app;

    public TwinClientsTests(TwinClientsApp app) => _app = app;

    [Fact]
    public async Task TwoClientsWithTheSameNameAreTwoHeadingsAndTheTableStillRedraws()
    {
        await using var page = await LivePage.OpenAsync<DomainsPage>(_app);

        static int Headings(string html) => html.Split("scope=\"rowgroup\"").Length - 1;

        // Acme Corp from the seed, and the two Twins.
        Assert.Equal(3, Headings(await page.HtmlAsync()));

        // Flat and back again: the second draw is the one that compares the
        // two headings, which read exactly alike.
        await page.ClickAsync(label => label.StartsWith("Volume", StringComparison.Ordinal), "the Volume header");
        Assert.Equal(0, Headings(await page.HtmlAsync()));

        await page.ClickAsync(label => label.StartsWith("Domain", StringComparison.Ordinal), "the Domain header");
        Assert.Equal(3, Headings(await page.HtmlAsync()));
    }
}

public sealed class TwinClientsApp : SeededApp
{
    public TwinClientsApp() => Extend().GetAwaiter().GetResult();

    private async Task Extend()
    {
        var store = new ReportStore(DatabasePath);

        foreach (var domain in new[] { "twin1.example", "twin2.example", "twin3.example", "twin4.example" })
        {
            await BookApp.StoreAsync(store, domain, passing: 10, failing: 0);
        }

        // Two clients, one name: told apart by their slugs, as the schema allows.
        var first = await store.CreateClientAsync("Twin", slug: "twin-a");
        await store.AssignDomainAsync("twin1.example", first!);
        await store.AssignDomainAsync("twin2.example", first!);

        var second = await store.CreateClientAsync("Twin", slug: "twin-b");
        await store.AssignDomainAsync("twin3.example", second!);
        await store.AssignDomainAsync("twin4.example", second!);
    }
}

/// <summary>
/// The seeded install with a second client that has one domain and a third
/// that has two, so a table of five domains has one heading too few and one
/// too many to be mistaken for either extreme.
/// </summary>
public sealed class BookApp : SeededApp
{
    public BookApp() => Extend().GetAwaiter().GetResult();

    private async Task Extend()
    {
        var store = new ReportStore(DatabasePath);

        await StoreAsync(store, "bravo.example", passing: 500, failing: 50);
        await StoreAsync(store, "charlie.example", passing: 100, failing: 0);
        await StoreAsync(store, "delta.example", passing: 30, failing: 30);

        var bravo = await store.CreateClientAsync("Bravo Inc");
        await store.AssignDomainAsync("bravo.example", bravo!);

        var charlie = await store.CreateClientAsync("Charlie LLC");
        await store.AssignDomainAsync("charlie.example", charlie!);
        await store.AssignDomainAsync("delta.example", charlie!);
    }

    /// <summary>A recent report for <paramref name="domain"/> at p=none, with the given mail passing and failing.</summary>
    internal static async Task StoreAsync(ReportStore store, string domain, int passing, int failing)
    {
        var begin = DateTimeOffset.UtcNow.AddDays(-2);
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
              <record>
                <row>
                  <source_ip>192.0.2.200</source_ip><count>{passing}</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>{domain}</header_from></identifiers>
                <auth_results>
                  <dkim><domain>{domain}</domain><selector>s1</selector><result>pass</result></dkim>
                  <spf><domain>{domain}</domain><result>pass</result></spf>
                </auth_results>
              </record>
              <record>
                <row>
                  <source_ip>192.0.2.201</source_ip><count>{failing}</count>
                  <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
                </row>
                <identifiers><header_from>{domain}</header_from></identifiers>
                <auth_results>
                  <dkim><domain>{domain}</domain><selector>s1</selector><result>fail</result></dkim>
                  <spf><domain>{domain}</domain><result>fail</result></spf>
                </auth_results>
              </record>
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        if (!parsed.Success) { throw new InvalidOperationException($"seed report did not parse: {parsed.Error}"); }
        await store.SaveAggregateAsync(parsed.Report!, xml, null);
    }
}
